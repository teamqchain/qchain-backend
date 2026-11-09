package api

// Test fixtures for this package's tests. They are copies of the ones in
// pqc/commitment_test.go and pqc/testhelpers_test.go: Go test files cannot be
// imported from another package, so each package keeps its own small copy.

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"

	"github.com/teamqchain/qchain-backend/pqc"
)

var (
	testHashA = strings.Repeat("a", 64)
	testSaltA = "0123456789abcdef0123456789abcdef"
)

// testDSAKeyPair returns a fresh ML-DSA-44 key pair as hex (public, secret).
func testDSAKeyPair(t *testing.T) (pubHex, secHex string) {
	t.Helper()
	signer := oqs.Signature{}
	defer signer.Clean()
	if err := signer.Init(pqc.SigName, nil); err != nil {
		t.Fatalf("init %s: %v", pqc.SigName, err)
	}
	pub, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate %s key pair: %v", pqc.SigName, err)
	}
	return hex.EncodeToString(pub), hex.EncodeToString(signer.ExportSecretKey())
}
