package proxyca

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/seoo2001/mcp-gate/internal/cryptox"
)

func mustKEK(t *testing.T) []byte {
	t.Helper()
	k, err := cryptox.RandomBytes(cryptox.AESKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestLoadOrCreate_GeneratesAndReloads(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	kek := mustKEK(t)

	ca1, err := LoadOrCreate(certPath, keyPath, kek)
	if err != nil {
		t.Fatal(err)
	}
	if ca1.Cert.Subject.CommonName == "" {
		t.Fatal("empty CN on generated CA")
	}
	for _, p := range []string{certPath, keyPath} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := st.Mode().Perm(), os.FileMode(0o600); got != want {
			t.Fatalf("%s mode = %v, want %v", p, got, want)
		}
	}
	// Reload returns the same cert (serial number identifies uniqueness).
	ca2, err := LoadOrCreate(certPath, keyPath, kek)
	if err != nil {
		t.Fatal(err)
	}
	if ca1.Cert.SerialNumber.Cmp(ca2.Cert.SerialNumber) != 0 {
		t.Fatalf("reload produced different cert")
	}
}

func TestLoadOrCreate_WrongKEKFails(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	if _, err := LoadOrCreate(certPath, keyPath, mustKEK(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(certPath, keyPath, mustKEK(t)); err == nil {
		t.Fatalf("expected decrypt failure with new KEK")
	}
}

func TestIssueLeafChainsToRoot(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), mustKEK(t))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _, err := ca.IssueLeaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "api.github.com"}); err != nil {
		t.Fatalf("leaf verify failed: %v", err)
	}
}

func TestIssueLeafTLSConfigUsable(t *testing.T) {
	// Sanity: leaf + key are usable in a tls.Config without TLS handshake errors.
	dir := t.TempDir()
	ca, err := LoadOrCreate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), mustKEK(t))
	if err != nil {
		t.Fatal(err)
	}
	leaf, key, err := ca.IssueLeaf("example.test")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leaf.Raw},
			PrivateKey:  key,
			Leaf:        leaf,
		}},
	}
	if cfg.Certificates[0].Leaf.Subject.CommonName != "example.test" {
		t.Fatalf("leaf CN wrong")
	}
}
