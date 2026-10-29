// mkwallet builds a Fabric wallet ".id" file (the JSON shape fabric.go's
// loadWalletIdentity reads) from an MSP directory, from cryptogen or
// fabric-ca-client: the signing certificate in signcerts/ and the PKCS#8
// private key in keystore/. Of the keystore's *_sk files, the one whose
// public key matches the certificate is used.
//
// The key is checked against the certificate (public keys must match) but is
// never printed. The .id file contains the private key and is written 0600.
//
// Usage:
//
//	go run ./cmd/mkwallet <msp dir> <mspID> <output .id file>
//	go run ./cmd/mkwallet .../users/issuer1@government.uae.com/msp GovernmentMSP wallet/government/issuer1.id
package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type walletID struct {
	Credentials struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"privateKey"`
	} `json:"credentials"`
	MspID   string `json:"mspId"`
	Type    string `json:"type"`
	Version int    `json:"version"`
}

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("usage: %s <msp dir> <mspID> <output .id file>", filepath.Base(os.Args[0]))
	}
	mspDir, mspID, out := os.Args[1], os.Args[2], os.Args[3]

	certPEM, err := onlyFile(filepath.Join(mspDir, "signcerts"))
	if err != nil {
		log.Fatal(err)
	}
	keyPEM, err := matchingKey(filepath.Join(mspDir, "keystore"), certPEM)
	if err != nil {
		log.Fatal(err)
	}

	var id walletID
	id.Credentials.Certificate = string(certPEM)
	id.Credentials.PrivateKey = string(keyPEM)
	id.MspID = mspID
	id.Type = "X.509"
	id.Version = 1
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(out, data, 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s (mspId %s)\n", out, mspID)
}

// onlyFile returns the contents of the single file in dir.
func onlyFile(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e.Name())
		}
	}
	if len(files) != 1 {
		return nil, fmt.Errorf("expected exactly one file in %s, found %d", dir, len(files))
	}
	return os.ReadFile(filepath.Join(dir, files[0]))
}

// matchingKey returns the private key in dir that matches certPEM. It looks
// at every *_sk file, as a keystore can hold more than one key: fabric-ca
// keeps the old key on reenroll. Exactly one file must match.
func matchingKey(dir string, certPEM []byte) ([]byte, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*_sk"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no *_sk private key file in %s", dir)
	}
	var matches []string
	var keyPEM []byte
	var reasons []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if err := checkKeyMatchesCert(certPEM, data); err != nil {
			reasons = append(reasons, fmt.Sprintf("%s: %v", filepath.Base(f), err))
			continue
		}
		matches = append(matches, filepath.Base(f))
		keyPEM = data
	}
	switch len(matches) {
	case 1:
		return keyPEM, nil
	case 0:
		return nil, fmt.Errorf("none of the %d *_sk files in %s matches the signing certificate (%s)", len(files), dir, strings.Join(reasons, "; "))
	default:
		return nil, fmt.Errorf("%d *_sk files in %s match the signing certificate (%s); keep one", len(matches), dir, strings.Join(matches, ", "))
	}
}

func checkKeyMatchesCert(certPEM, keyPEM []byte) error {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return fmt.Errorf("signing certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return fmt.Errorf("private key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return fmt.Errorf("parsing PKCS#8 private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key %T cannot sign", key)
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return fmt.Errorf("private key does not match the certificate's public key")
	}
	return nil
}
