package cryptox

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := RandomBytes(AESKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("ghp_super_secret_token_value")
	aad := []byte("github")
	sealed, err := SealAES256GCM(key, pt, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := OpenAES256GCM(key, sealed, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestNonceIsFreshPerSeal(t *testing.T) {
	key, _ := RandomBytes(AESKeyLen)
	a, _ := SealAES256GCM(key, []byte("x"), nil)
	b, _ := SealAES256GCM(key, []byte("x"), nil)
	if bytes.Equal(a.Nonce, b.Nonce) {
		t.Fatalf("nonce collision: same plaintext produced same nonce twice")
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatalf("ciphertext identical → nonce reuse")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	key, _ := RandomBytes(AESKeyLen)
	sealed, _ := SealAES256GCM(key, []byte("hello"), nil)
	sealed.Ciphertext[0] ^= 0x01
	if _, err := OpenAES256GCM(key, sealed, nil); err == nil {
		t.Fatalf("expected auth failure on tampered ct")
	}
}

func TestOpenRejectsWrongAAD(t *testing.T) {
	key, _ := RandomBytes(AESKeyLen)
	sealed, _ := SealAES256GCM(key, []byte("hello"), []byte("github"))
	if _, err := OpenAES256GCM(key, sealed, []byte("slack")); err == nil {
		t.Fatalf("expected auth failure on AAD mismatch")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	k1, _ := RandomBytes(AESKeyLen)
	k2, _ := RandomBytes(AESKeyLen)
	sealed, _ := SealAES256GCM(k1, []byte("hello"), nil)
	if _, err := OpenAES256GCM(k2, sealed, nil); err == nil {
		t.Fatalf("expected auth failure on wrong key")
	}
}

func TestSealRejectsBadKeyLength(t *testing.T) {
	if _, err := SealAES256GCM(make([]byte, 16), []byte("x"), nil); err == nil {
		t.Fatalf("expected key-length error")
	}
}

func TestRandomBytesRejectsNonPositive(t *testing.T) {
	if _, err := RandomBytes(0); err == nil {
		t.Fatalf("expected error for n=0")
	}
}
