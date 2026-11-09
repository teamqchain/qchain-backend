package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadWalletIdentity covers parsing of wallet/<org>/<identity>.id files.
// Each subtest maps to a real-world failure mode seen during gateway setup.
func TestLoadWalletIdentity(t *testing.T) {
	oldNetworkRoot := networkRoot
	tempRoot := t.TempDir()
	networkRoot = tempRoot
	defer func() { networkRoot = oldNetworkRoot }()

	org := "government"
	identityName := "alice"
	idDir := filepath.Join(walletDir(org))
	if err := os.MkdirAll(idDir, 0o755); err != nil {
		t.Fatalf("setup failed: could not create wallet dir: %v", err)
	}

	// Happy path: a complete identity file returns certificate and private key.
	t.Run("success", func(t *testing.T) {
		idPath := filepath.Join(idDir, identityName+".id")
		content := `{"credentials":{"certificate":"CERT","privateKey":"KEY"},"mspId":"GovernmentMSP","type":"X.509","version":1}`
		if err := os.WriteFile(idPath, []byte(content), 0o644); err != nil {
			t.Fatalf("setup failed: could not write wallet identity file: %v", err)
		}

		certPEM, keyPEM, err := loadWalletIdentity(org, identityName)
		if err != nil {
			t.Fatalf("expected valid wallet identity to load; likely parser/path issue: %v", err)
		}
		if string(certPEM) != "CERT" || string(keyPEM) != "KEY" {
			t.Fatalf("wallet identity values mismatch. got cert=%q key=%q", string(certPEM), string(keyPEM))
		}
	})

	// Missing file should surface a clear "not found" style error for operators.
	t.Run("missing file", func(t *testing.T) {
		_, _, err := loadWalletIdentity(org, "missing-user")
		if err == nil {
			t.Fatalf("expected error for missing wallet file; got nil")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Fatalf("expected missing-file hint in error. got: %v", err)
		}
	})

	// Malformed JSON should fail early with a parse-focused error message.
	t.Run("invalid json", func(t *testing.T) {
		idPath := filepath.Join(idDir, "broken.id")
		if err := os.WriteFile(idPath, []byte("{not-json"), 0o644); err != nil {
			t.Fatalf("setup failed: could not write malformed identity file: %v", err)
		}

		_, _, err := loadWalletIdentity(org, "broken")
		if err == nil {
			t.Fatalf("expected JSON parsing error for malformed wallet file; got nil")
		}
		if !strings.Contains(err.Error(), "parsing wallet .id file") {
			t.Fatalf("error should mention parse failure for easier diagnosis. got: %v", err)
		}
	})

	// Certificate is mandatory for X.509 identity creation.
	t.Run("missing certificate", func(t *testing.T) {
		idPath := filepath.Join(idDir, "nocert.id")
		content := `{"credentials":{"certificate":"","privateKey":"KEY"},"mspId":"GovernmentMSP","type":"X.509","version":1}`
		if err := os.WriteFile(idPath, []byte(content), 0o644); err != nil {
			t.Fatalf("setup failed: could not write missing-cert identity file: %v", err)
		}

		_, _, err := loadWalletIdentity(org, "nocert")
		if err == nil {
			t.Fatalf("expected certificate validation error; got nil")
		}
		if !strings.Contains(err.Error(), "has no certificate") {
			t.Fatalf("error should indicate missing certificate. got: %v", err)
		}
	})

	// Private key is mandatory for request signing.
	t.Run("missing private key", func(t *testing.T) {
		idPath := filepath.Join(idDir, "nokey.id")
		content := `{"credentials":{"certificate":"CERT","privateKey":""},"mspId":"GovernmentMSP","type":"X.509","version":1}`
		if err := os.WriteFile(idPath, []byte(content), 0o644); err != nil {
			t.Fatalf("setup failed: could not write missing-key identity file: %v", err)
		}

		_, _, err := loadWalletIdentity(org, "nokey")
		if err == nil {
			t.Fatalf("expected private key validation error; got nil")
		}
		if !strings.Contains(err.Error(), "has no privateKey") {
			t.Fatalf("error should indicate missing privateKey. got: %v", err)
		}
	})
}
