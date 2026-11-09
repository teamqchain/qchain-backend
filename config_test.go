package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestGetEnv verifies the environment override helper used by runtime config.
// New contributors can read this as: env value wins, otherwise fallback is used.
func TestGetEnv(t *testing.T) {
	const key = "QCHAIN_TEST_ENV_KEY"

	if err := os.Setenv(key, "configured"); err != nil {
		t.Fatalf("setup failed: could not set env var %q: %v", key, err)
	}
	defer os.Unsetenv(key)

	if got := getEnv(key, "fallback"); got != "configured" {
		t.Fatalf("getEnv should return configured value when env var exists. got=%q want=%q", got, "configured")
	}

	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("setup failed: could not unset env var %q: %v", key, err)
	}

	if got := getEnv(key, "fallback"); got != "fallback" {
		t.Fatalf("getEnv should return fallback when env var is missing. got=%q want=%q", got, "fallback")
	}
}

// TestPathHelpers validates how filesystem paths are derived from networkRoot.
// These helpers are critical because most runtime failures come from wrong paths.
func TestPathHelpers(t *testing.T) {
	oldNetworkRoot := networkRoot
	networkRoot = "/tmp/qchain-network"
	defer func() { networkRoot = oldNetworkRoot }()

	if got := mspDir("government"); got != "/tmp/qchain-network/crypto-material/peerOrganizations/government.uae.com" {
		t.Fatalf("mspDir returned unexpected path. likely wrong org-domain mapping. got=%q", got)
	}

	if got := mspDir("customorg"); got != "/tmp/qchain-network/crypto-material/peerOrganizations/customorg.uae.com" {
		t.Fatalf("mspDir fallback domain logic seems broken for unknown org. got=%q", got)
	}

	if got := walletDir("general"); got != "/tmp/qchain-network/wallet/general" {
		t.Fatalf("walletDir returned unexpected path. likely wrong networkRoot usage. got=%q", got)
	}
}

// TestDubaiTimezoneFormat verifies expiry time format in Asia/Dubai has no Z suffix.
func TestDubaiTimezoneFormat(t *testing.T) {
	loc := mustLoadLocation("Asia/Dubai")
	now := time.Now().In(loc)
	formatted := now.Format("2006-01-02T15:04:05")
	if strings.HasSuffix(formatted, "Z") {
		t.Fatalf("Dubai timezone format should not contain UTC 'Z' suffix: %s", formatted)
	}
	if len(formatted) != 19 || formatted[10] != 'T' {
		t.Fatalf("unexpected format for Dubai time: %s", formatted)
	}
}
