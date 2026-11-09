package pqc

import (
	"testing"
)

// TestPQCSignVerifyRoundTrip checks the cryptographic flow used by credentials:
// generate key pair -> sign -> verify, plus a tamper check.
func TestPQCSignVerifyRoundTrip(t *testing.T) {
	pub, priv := testDSAKeyPair(t)

	message := "credential-payload"
	sig, err := PqcSign(message, priv)
	if err != nil {
		t.Fatalf("PQC signing failed; private key handling may be broken: %v", err)
	}

	valid, err := PqcVerify(message, sig, pub)
	if err != nil {
		t.Fatalf("PQC verification failed unexpectedly; verify path may be broken: %v", err)
	}
	if !valid {
		t.Fatalf("expected valid signature for original message; got invalid")
	}

	tamperedValid, err := PqcVerify(message+"-tampered", sig, pub)
	if err != nil {
		t.Fatalf("tampered-message verification returned error instead of false: %v", err)
	}
	if tamperedValid {
		t.Fatalf("tampered message incorrectly verified as valid; signature integrity check likely broken")
	}
}

// TestPQCDecodeFailures ensures invalid hex input fails fast with errors
// instead of silently producing incorrect cryptographic behavior.
func TestPQCDecodeFailures(t *testing.T) {
	if _, err := PqcSign("msg", "not-hex"); err == nil {
		t.Fatalf("expected hex decode error for invalid private key input")
	}

	if _, err := PqcVerify("msg", "not-hex", "also-not-hex"); err == nil {
		t.Fatalf("expected hex decode error for invalid signature/public key input")
	}
}

// TestMLDSAPresentationSigning verifies end-to-end holder presentation signing:
// generating an ML-DSA-44 keypair, signing the SHA3-256 hash of canonical JSON,
// and verifying with public key + detecting tampered payloads or key substitutions.
func TestMLDSAPresentationSigning(t *testing.T) {
	// 1. Generate holder's ML-DSA-44 key pair
	holderPub, holderPriv := testDSAKeyPair(t)

	// 2. Build canonical presentation payload
	disclosedPayload := `{"credentialID":"CRED-2026-001","disclosedFields":{"college":"CCI","degreeTitle":"BSc Computer Science","gpa":"3.8"},"timestamp":"2026-09-22T13:00:00"}`
	payloadHash := Sha3Hex(disclosedPayload)

	// 3. Holder signs hash with private key
	sig, err := PqcSign(payloadHash, holderPriv)
	if err != nil {
		t.Fatalf("pqcSign failed: %v", err)
	}

	// 4. Verifier verifies signature with holder public key
	valid, err := PqcVerify(payloadHash, sig, holderPub)
	if err != nil {
		t.Fatalf("pqcVerify returned error: %v", err)
	}
	if !valid {
		t.Fatalf("expected holder presentation signature to verify successfully")
	}

	// 5. Tampered payload (e.g. gpa modified 3.8 -> 4.0) must fail verification
	tamperedPayload := `{"credentialID":"CRED-2026-001","disclosedFields":{"college":"CCI","degreeTitle":"BSc Computer Science","gpa":"4.0"},"timestamp":"2026-09-22T13:00:00"}`
	tamperedHash := Sha3Hex(tamperedPayload)
	tamperedValid, _ := PqcVerify(tamperedHash, sig, holderPub)
	if tamperedValid {
		t.Fatalf("expected signature verification to fail for tampered payload")
	}

	// 6. Presentation verified with different holder's public key must fail
	otherPub, _ := testDSAKeyPair(t)
	otherKeyValid, _ := PqcVerify(payloadHash, sig, otherPub)
	if otherKeyValid {
		t.Fatalf("expected signature verification to fail with wrong holder public key")
	}
}
