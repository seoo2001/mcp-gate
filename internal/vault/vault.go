// Package vault is the credential store. It persists service → token
// mappings to a JSON file under $MCP_GATE_HOME using envelope encryption:
//
//	plaintext PAT  ── AES-256-GCM(DEK) ──▶ encrypted PAT  ┐
//	random DEK     ── AES-256-GCM(KEK) ──▶ encrypted DEK  ┘ (per record)
//	KEK            ── lives in keystore (Keychain / file fallback)
//
// Why envelope rather than encrypting all records under the KEK directly:
//   - re-keying a record (rotating the DEK) doesn't require the KEK,
//   - exposing one DEK leaks one record, not all of them,
//   - we can ship the encrypted vault in backups without exporting the KEK.
//
// The on-disk format is intentionally line-stable JSON so users can `diff`
// two vault snapshots and see exactly what changed.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/seoo2001/mcp-gate/internal/cryptox"
	"github.com/seoo2001/mcp-gate/internal/keystore"
)

// FormatVersion is bumped when the on-disk schema changes. Old vaults with a
// lower version trigger a migration path (none defined yet for v1).
const FormatVersion = 1

// ErrNotFound is returned by Get/Remove when the service has no record.
var ErrNotFound = errors.New("vault: service not found")

// Record is one credential entry. Plaintext never lives on disk.
//
//	┌──────────────────┐ ┌──────────────────────┐
//	│ DEK (32B random) │→│ Sealed under KEK     │ DEK
//	└──────────────────┘ └──────────────────────┘
//	                        ▼
//	┌──────────────────┐ ┌──────────────────────┐
//	│ PAT (utf-8)      │→│ Sealed under DEK,    │ Value
//	│                  │ │ AAD = service name   │
//	└──────────────────┘ └──────────────────────┘
type Record struct {
	Service     string         `json:"service"`
	DEK         cryptox.Sealed `json:"dek"`
	Value       cryptox.Sealed `json:"value"`
	CreatedUnix int64          `json:"created_unix"`
	UpdatedUnix int64          `json:"updated_unix"`
}

// fileFormat is the persisted JSON document.
type fileFormat struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

// Vault is the in-memory + on-disk credential store. Safe for concurrent use.
type Vault struct {
	path string
	kek  []byte
	now  func() time.Time

	mu      sync.RWMutex
	records map[string]Record
}

// Open loads (or initialises) a vault at path using ks for the master key.
func Open(ctx context.Context, path string, ks keystore.Keystore) (*Vault, error) {
	if path == "" {
		return nil, errors.New("vault: empty path")
	}
	kek, err := ks.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("vault: load master key: %w", err)
	}
	if len(kek) != cryptox.AESKeyLen {
		return nil, fmt.Errorf("vault: master key length = %d, want %d", len(kek), cryptox.AESKeyLen)
	}
	v := &Vault{
		path:    path,
		kek:     kek,
		now:     time.Now,
		records: map[string]Record{},
	}
	if err := v.reload(); err != nil {
		return nil, err
	}
	return v, nil
}

// reload reads the file (if present) into v.records.
func (v *Vault) reload() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, err := os.ReadFile(v.path)
	if errors.Is(err, fs.ErrNotExist) {
		v.records = map[string]Record{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("vault: read %q: %w", v.path, err)
	}
	if len(b) == 0 {
		v.records = map[string]Record{}
		return nil
	}
	var ff fileFormat
	if err := json.Unmarshal(b, &ff); err != nil {
		return fmt.Errorf("vault: parse %q: %w", v.path, err)
	}
	if ff.Version != FormatVersion {
		return fmt.Errorf("vault: unsupported format version %d (want %d)", ff.Version, FormatVersion)
	}
	out := make(map[string]Record, len(ff.Records))
	for _, r := range ff.Records {
		out[r.Service] = r
	}
	v.records = out
	return nil
}

// persist writes records back to disk atomically (mode 0600).
func (v *Vault) persist() error {
	names := make([]string, 0, len(v.records))
	for n := range v.records {
		names = append(names, n)
	}
	sort.Strings(names)
	out := fileFormat{Version: FormatVersion, Records: make([]Record, 0, len(names))}
	for _, n := range names {
		out.Records = append(out.Records, v.records[n])
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("vault: marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return fmt.Errorf("vault: mkdir: %w", err)
	}
	return writeAtomic(v.path, b, 0o600)
}

// Add (or replace) a credential. AAD = service name → tampering with the
// "service" key in the JSON makes Get fail authentication.
func (v *Vault) Add(_ context.Context, service, token string) error {
	if service == "" {
		return errors.New("vault: empty service name")
	}
	if token == "" {
		return errors.New("vault: empty token")
	}
	dek, err := cryptox.RandomBytes(cryptox.AESKeyLen)
	if err != nil {
		return err
	}
	dekSealed, err := cryptox.SealAES256GCM(v.kek, dek, []byte("dek:"+service))
	if err != nil {
		return fmt.Errorf("vault: seal dek: %w", err)
	}
	valSealed, err := cryptox.SealAES256GCM(dek, []byte(token), []byte("value:"+service))
	if err != nil {
		return fmt.Errorf("vault: seal value: %w", err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now().Unix()
	created := now
	if existing, ok := v.records[service]; ok {
		created = existing.CreatedUnix
	}
	v.records[service] = Record{
		Service:     service,
		DEK:         dekSealed,
		Value:       valSealed,
		CreatedUnix: created,
		UpdatedUnix: now,
	}
	return v.persist()
}

// Get returns the plaintext token for service.
func (v *Vault) Get(_ context.Context, service string) (string, error) {
	v.mu.RLock()
	rec, ok := v.records[service]
	v.mu.RUnlock()
	if !ok {
		return "", ErrNotFound
	}
	dek, err := cryptox.OpenAES256GCM(v.kek, rec.DEK, []byte("dek:"+service))
	if err != nil {
		return "", fmt.Errorf("vault: unseal dek: %w", err)
	}
	defer wipe(dek)
	pt, err := cryptox.OpenAES256GCM(dek, rec.Value, []byte("value:"+service))
	if err != nil {
		return "", fmt.Errorf("vault: unseal value: %w", err)
	}
	return string(pt), nil
}

// Remove deletes a service record. Returns ErrNotFound if absent.
func (v *Vault) Remove(_ context.Context, service string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.records[service]; !ok {
		return ErrNotFound
	}
	delete(v.records, service)
	return v.persist()
}

// List returns service names sorted ascending.
func (v *Vault) List(_ context.Context) ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]string, 0, len(v.records))
	for n := range v.records {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// Has reports whether a service exists in the vault.
func (v *Vault) Has(service string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.records[service]
	return ok
}

// Close zeroes the in-memory KEK. After Close, all methods will fail.
// Useful for tests; in normal CLI use the process simply exits.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	wipe(v.kek)
	v.kek = nil
	v.records = nil
	return nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
