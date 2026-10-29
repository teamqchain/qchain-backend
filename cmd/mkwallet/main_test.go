package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mldsaKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ecdsaKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func certFor(t *testing.T, k crypto.Signer) []byte {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "alice"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPEM(t *testing.T, k crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// keystore writes the given files (name -> contents) to a new directory.
func keystore(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// requireKey fails unless got is want; it never prints key material.
func requireKey(t *testing.T, got, want []byte, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("matchingKey returned the wrong key")
	}
}

func requireErr(t *testing.T, got []byte, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error %v, want one containing %q", err, want)
	}
	if got != nil {
		t.Fatal("a key was returned with the error")
	}
}

func TestMatchingKeyOneKey(t *testing.T) {
	for name, k := range map[string]crypto.Signer{"ML-DSA-44": mldsaKey(t), "ECDSA P-256": ecdsaKey(t)} {
		t.Run(name, func(t *testing.T) {
			// cryptogen names its key priv_sk, fabric-ca-client <ski>_sk.
			for _, file := range []string{"priv_sk", "0123abcd_sk"} {
				dir := keystore(t, map[string][]byte{file: keyPEM(t, k)})
				got, err := matchingKey(dir, certFor(t, k))
				requireKey(t, got, keyPEM(t, k), err)
			}
		})
	}
}

// After a fabric-ca reenroll, the keystore holds the old key and the new one.
func TestMatchingKeySecondOfTwoMatches(t *testing.T) {
	oldKey, newKey := mldsaKey(t), mldsaKey(t)
	dir := keystore(t, map[string][]byte{"aaaa_sk": keyPEM(t, oldKey), "bbbb_sk": keyPEM(t, newKey)})
	got, err := matchingKey(dir, certFor(t, newKey))
	requireKey(t, got, keyPEM(t, newKey), err)
}

func TestMatchingKeyNoneMatches(t *testing.T) {
	dir := keystore(t, map[string][]byte{"aaaa_sk": keyPEM(t, mldsaKey(t)), "bbbb_sk": keyPEM(t, ecdsaKey(t))})
	got, err := matchingKey(dir, certFor(t, mldsaKey(t)))
	requireErr(t, got, err, "none of the 2 *_sk files in "+dir+" matches the signing certificate")
}

func TestMatchingKeyTwoMatch(t *testing.T) {
	k := mldsaKey(t)
	dir := keystore(t, map[string][]byte{"priv_sk": keyPEM(t, k), "cccc_sk": keyPEM(t, k)})
	got, err := matchingKey(dir, certFor(t, k))
	requireErr(t, got, err, "2 *_sk files in "+dir+" match the signing certificate (cccc_sk, priv_sk); keep one")
}

func TestMatchingKeyNoSkFiles(t *testing.T) {
	k := mldsaKey(t)
	dir := keystore(t, map[string][]byte{"key.pem": keyPEM(t, k)})
	got, err := matchingKey(dir, certFor(t, k))
	requireErr(t, got, err, "no *_sk private key file in "+dir)
}

// Files that are not *_sk are ignored, and a *_sk file that is not a key is
// reported by name without its contents.
func TestMatchingKeyIgnoresOtherFiles(t *testing.T) {
	k := mldsaKey(t)
	dir := keystore(t, map[string][]byte{"README": []byte("not a key"), "junk_sk": []byte("not a key"), "dddd_sk": keyPEM(t, k)})
	got, err := matchingKey(dir, certFor(t, k))
	requireKey(t, got, keyPEM(t, k), err)

	dir = keystore(t, map[string][]byte{"junk_sk": []byte("not a key")})
	got, err = matchingKey(dir, certFor(t, k))
	requireErr(t, got, err, "junk_sk: private key is not PEM")
}
