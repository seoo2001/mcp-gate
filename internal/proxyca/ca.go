// Package proxyca generates and persists the local Certificate Authority
// used by the MITM proxy.
//
// Why a custom CA: to intercept HTTPS, the proxy must present a leaf
// certificate the client trusts. Real upstream certs (e.g. from DigiCert)
// can't be impersonated. Instead, mcp-gate ships a per-installation root CA;
// the user trusts it once at install time, and the proxy mints leaves on
// demand for every Host the wrapped MCP server contacts.
//
// The CA private key is encrypted at rest with the keystore master key
// (envelope encryption again). Without the master key, an attacker with
// disk access cannot impersonate the proxy.
//
// On disk:
//
//	ca.pem  — public certificate, world-readable (clients need it to trust)
//	ca.key  — encrypted PEM bundle of {nonce, ciphertext} of the DER private key
package proxyca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/seoo2001/mcp-gate/internal/cryptox"
)

// CA is the loaded certificate + signing key.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	// CertPEM is the user-facing public cert (for trust-store install).
	CertPEM []byte
}

// CAValidity is how long the root CA stays valid. 10 years gives users a
// long-enough window that they almost never re-trust, but not "forever"
// (which makes incident response harder).
const CAValidity = 10 * 365 * 24 * time.Hour

// LoadOrCreate reads the CA from certPath/keyPath, generating a fresh one if
// either file is missing. The private key is decrypted with kek (the vault
// master key). All files are mode 0600.
func LoadOrCreate(certPath, keyPath string, kek []byte) (*CA, error) {
	if len(kek) != cryptox.AESKeyLen {
		return nil, fmt.Errorf("proxyca: invalid kek length %d", len(kek))
	}
	ca, err := load(certPath, keyPath, kek)
	if err == nil {
		return ca, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return create(certPath, keyPath, kek)
}

func load(certPath, keyPath string, kek []byte) (*CA, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("proxyca: cert PEM decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("proxyca: parse cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || keyBlock.Type != "MCP-GATE ENCRYPTED EC PRIVATE KEY" {
		return nil, errors.New("proxyca: key PEM decode failed")
	}
	var sealed cryptox.Sealed
	if err := json.Unmarshal(keyBlock.Bytes, &sealed); err != nil {
		return nil, fmt.Errorf("proxyca: parse encrypted key wrapper: %w", err)
	}
	der, err := cryptox.OpenAES256GCM(kek, sealed, []byte("proxy-ca-key"))
	if err != nil {
		return nil, fmt.Errorf("proxyca: decrypt key: %w", err)
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("proxyca: parse key DER: %w", err)
	}
	return &CA{Cert: cert, Key: key, CertPEM: certBytes}, nil
}

func create(certPath, keyPath string, kek []byte) (*CA, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proxyca: gen key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("proxyca: gen serial: %w", err)
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "mcp-gate local CA",
			Organization: []string{"mcp-gate"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:             0,
		MaxPathLenZero:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("proxyca: sign cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("proxyca: re-parse cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("proxyca: marshal key: %w", err)
	}
	sealed, err := cryptox.SealAES256GCM(kek, keyDER, []byte("proxy-ca-key"))
	if err != nil {
		return nil, fmt.Errorf("proxyca: encrypt key: %w", err)
	}
	wrapper, err := json.Marshal(sealed)
	if err != nil {
		return nil, fmt.Errorf("proxyca: marshal encrypted wrapper: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "MCP-GATE ENCRYPTED EC PRIVATE KEY",
		Bytes: wrapper,
	})

	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return nil, err
	}
	if err := writeFile(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: priv, CertPEM: certPEM}, nil
}

func writeFile(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ca-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// IssueLeaf signs a leaf certificate for hostname using the CA. Used by the
// MITM proxy at runtime; certs are short-lived (24 h) since the proxy itself
// rebuilds them on the fly each session.
//
// If hostname is a literal IP address, it lands in IPAddresses (RFC 5280
// §4.2.1.6); otherwise in DNSNames. Modern TLS clients reject IP CONNECT
// targets that lack an IP SAN regardless of CN.
func (c *CA) IssueLeaf(hostname string) (cert *x509.Certificate, key *ecdsa.PrivateKey, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(hostname); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{hostname}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &priv.PublicKey, c.Key)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return leaf, priv, nil
}
