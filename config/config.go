package config

// config.go — process configuration and shared constants.
//
// Everything here is read once at startup from environment variables (with safe
// fallbacks) and then treated as read-only for the rest of the program. Keeping
// it in one file means there is a single place to look when you want to know
// "what knobs can the deployment turn?".
//
// Package config is imported by the main package and by api, ledger and pqc;
// the names they use are exported (capitalised), e.g. config.ChannelName.

import (
	"os"
	"path/filepath"
	"time"

	// Embed the IANA timezone database in the binary so time.LoadLocation
	// ("Asia/Dubai") works even in a minimal container that has no OS tzdata.
	// Without this, mustLoadLocation below silently falls back to UTC.
	_ "time/tzdata"
)

// ─────────────────────────────────────────────
//  CONFIGURATION (override via environment vars)
// ─────────────────────────────────────────────

// GetEnv returns the value of environment variable `key`, or `fallback` when
// the variable is unset/empty.
func GetEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var NetworkRoot = GetEnv("NETWORK_ROOT", "/qchain-network")

var (
	IpfsHost      = GetEnv("IPFS_HOST", "host.docker.internal:5001")
	ServerPort    = GetEnv("SERVER_PORT", "3000")
	ChannelName   = GetEnv("CHANNEL_NAME", "mychannel")
	ChaincodeName = GetEnv("CHAINCODE_NAME", "qchaincode")

	// All issuances use this org/identity from Fabric wallet — never sent by client.
	IssuerOrgName    = GetEnv("ISSUER_ORG", "general")
	IssuerIdentity   = GetEnv("ISSUER_IDENTITY", "issuer1")
	VerifierOrgName  = GetEnv("VERIFIER_ORG", "general")
	VerifierIdentity = GetEnv("VERIFIER_IDENTITY", "verifier1")

	// Org-level ML-DSA-44 key pair — loaded at startup from env, never generated per-credential.
	// These are assigned in main() (main.go); declared here so every package can read them.
	IssuerPrivKeyHex string
	IssuerPubKeyHex  string
	IssuerOrgID      string

	// OrgConfig maps an org short-name ("general"/"government") to its Fabric peer
	// endpoint and MSP ID. `struct { ... }` here is an anonymous struct type — the
	// map's value type is defined inline because it is only used here.
	OrgConfig = map[string]struct {
		PeerEndpoint string
		GatewayPeer  string
		MSPID        string
	}{
		"government": {
			PeerEndpoint: GetEnv("GOV_PEER_ENDPOINT", "peer0.government.uae.com:27051"),
			GatewayPeer:  GetEnv("GOV_GATEWAY_PEER", "peer0.government.uae.com"),
			MSPID:        "GovernmentMSP",
		},
		"general": {
			PeerEndpoint: GetEnv("GEN_PEER_ENDPOINT", "peer0.general.uae.com:29051"),
			GatewayPeer:  GetEnv("GEN_GATEWAY_PEER", "peer0.general.uae.com"),
			MSPID:        "GeneralMSP",
		},
	}
)

// IssuerActorID / issuerActorName are the attribution stamped on issued/revoked/
// suspended/restored events and audit logs until real authentication is wired up.
const IssuerActorID = "ISS-UOS-0001"
const IssuerActorName = "Mohammed Al Issuer"

// MspDir returns the on-disk path to an org's crypto-material directory.
func MspDir(orgLC string) string {
	domainMap := map[string]string{
		"government": "government.uae.com",
		"general":    "general.uae.com",
	}
	domain, ok := domainMap[orgLC]
	if !ok {
		domain = orgLC + ".uae.com"
	}
	return filepath.Join(NetworkRoot, "crypto-material", "peerOrganizations", domain)
}

// WalletDir returns the on-disk path to an org's Fabric wallet directory.
func WalletDir(orgLC string) string {
	return filepath.Join(NetworkRoot, "wallet", orgLC)
}

// MustLoadLocation loads a timezone (e.g. "Asia/Dubai"), falling back to UTC if
// the zone database is unavailable. Used so issuance timestamps are local time.
func MustLoadLocation(tz string) *time.Location {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.UTC
	}
	return loc
}
