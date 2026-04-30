package keystore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// FileKeystore writes the master key to a file at Path with mode 0600.
//
// This is the lowest-friction backend (works in CI, in headless Linux, on
// rooted dev VMs). Trade-off: anyone with disk-read on the user's home dir
// gets the key. Production users on macOS should prefer KeychainKeystore.
type FileKeystore struct {
	Path string
}

// Load returns the file-stored key, creating it on first call.
func (f *FileKeystore) Load(_ context.Context) ([]byte, error) {
	if f.Path == "" {
		return nil, errors.New("file keystore: empty path")
	}
	b, err := os.ReadFile(f.Path)
	if err == nil {
		raw, decErr := decode(string(b))
		if decErr != nil {
			return nil, fmt.Errorf("file keystore: decode %q: %w", f.Path, decErr)
		}
		if len(raw) != MasterKeyLen {
			return nil, fmt.Errorf("file keystore: master key length = %d, want %d", len(raw), MasterKeyLen)
		}
		return raw, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("file keystore: read %q: %w", f.Path, err)
	}
	// First run: generate, persist atomically.
	key, err := generate()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return nil, fmt.Errorf("file keystore: mkdir: %w", err)
	}
	if err := writeAtomic(f.Path, []byte(encode(key)), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// Reset removes the on-disk key. No error if already absent.
func (f *FileKeystore) Reset(_ context.Context) error {
	if f.Path == "" {
		return errors.New("file keystore: empty path")
	}
	if err := os.Remove(f.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("file keystore: remove %q: %w", f.Path, err)
	}
	return nil
}

// Backend returns the implementation name.
func (f *FileKeystore) Backend() string { return "file" }

// writeAtomic creates a sibling tempfile, writes, fsyncs, renames into place.
// On crash mid-write the original (or nothing) remains; never a partial file.
func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return fmt.Errorf("write atomic: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write atomic: write: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("write atomic: chmod: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write atomic: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write atomic: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("write atomic: rename: %w", err)
	}
	return nil
}
