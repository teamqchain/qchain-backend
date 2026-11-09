package main

// main.go — the program entry point.
//
// This file is deliberately small: it wires everything together but contains no
// business logic. Responsibilities:
//   • main()          — load keys/env, connect to MySQL, register every route on
//                       an http.ServeMux, and start the HTTP server.
//   • corsMiddleware  — allow the Flutter Web frontend (a different origin) to
//                       call this API from a browser.
//
// The actual handlers live in domain files in this same package (credentials.go,
// verification.go, mobile.go, ...). Because they are all `package main`, main()
// can reference them directly — no imports between files are needed. To find a
// handler, search for its name; to see the full URL map, read the mux block below.

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/teamqchain/qchain-backend/api"
	"github.com/teamqchain/qchain-backend/config"
	"github.com/teamqchain/qchain-backend/db"
	"github.com/teamqchain/qchain-backend/pqc"
)

// corsMiddleware sets CORS headers so Flutter Web can reach the API. It wraps the
// real router: every request passes through here first. OPTIONS (the browser's
// pre-flight check) is answered immediately; everything else falls through to next.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	config.
		// Load org-level ML-DSA-44 key pair — must be set in .env; fatal if missing.
		IssuerPrivKeyHex = os.Getenv("ISSUER_PRIVATE_KEY_HEX")
	config.IssuerPubKeyHex = os.Getenv("ISSUER_PUBLIC_KEY_HEX")
	config.IssuerOrgID = config.GetEnv("ISSUER_ORG_ID", "GeneralMSP")

	if config.IssuerPrivKeyHex == "" || config.IssuerPubKeyHex == "" {
		log.Fatal("ISSUER_PRIVATE_KEY_HEX and ISSUER_PUBLIC_KEY_HEX must be set — run `go run ./cmd/keygen` once to generate them")
	}

	// Track B2 / H — holder-level ML-KEM key pairs for OFF-CHAIN credential-data encryption.
	// Keys are generated on the holder's mobile device (QWallet) and registered via
	// POST /mobile/registerHolderKeys; the server never holds holder private keys.
	if n := pqc.ResolveKEMName(); n != "" {
		pqc.KemName = n
	}
	db.InitDB( // Connect to MySQL (non-fatal if not configured — warnings logged per request)
	)

	// One-shot migration mode: re-create holders (and their bound wallet keys)
	// on a freshly reset ledger from MySQL, then exit. Run with RUN_CHAIN_BOOTSTRAP=1.
	if os.Getenv("RUN_CHAIN_BOOTSTRAP") == "1" {
		runChainBootstrap()
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /registerHolder", api.HandleRegisterHolder)
	mux.HandleFunc("POST /issueCredential", api.HandleIssueCredential)
	mux.HandleFunc("POST /revokeCredential", api.HandleRevokeCredential)
	mux.HandleFunc("POST /suspendCredential", api.HandleSuspendCredential)
	mux.HandleFunc("POST /restoreCredential", api.HandleRestoreCredential)
	mux.HandleFunc("GET /getAllCredentials", api.HandleGetAllCredentials)
	mux.HandleFunc("GET /getHolders", api.HandleGetHolders)
	mux.HandleFunc("GET /getVerificationHistory", api.HandleGetVerificationHistory)
	mux.HandleFunc("GET /getDashboardStats", api.HandleGetDashboardStats)

	// Phase 2 — QPortal
	mux.HandleFunc("GET /getCredentialDetail", api.HandleGetCredentialDetail)
	mux.HandleFunc("POST /updateCredential", api.HandleUpdateCredential)
	mux.HandleFunc("GET /getVerificationDetail", api.HandleGetVerificationDetail)
	mux.HandleFunc("POST /resolveSession", api.HandleResolveSession)
	mux.HandleFunc("POST /requestSubscription", api.HandleRequestSubscription)
	mux.HandleFunc("GET /getSubscriptions", api.HandleGetSubscriptions)
	mux.HandleFunc("POST /deleteSubscription", api.HandleDeleteSubscription)
	mux.HandleFunc("POST /unsubscribe", api.HandleUnsubscribe)
	mux.HandleFunc("GET /getSubscriptionAlerts", api.HandleGetSubscriptionAlerts)
	mux.HandleFunc("POST /acknowledgeAlert", api.HandleAcknowledgeAlert)
	mux.HandleFunc("GET /getAuditLogs", api.HandleGetAuditLogs)
	mux.HandleFunc("GET /getStaff", api.HandleGetStaff)
	mux.HandleFunc("GET /getDirectory", api.HandleGetDirectory)
	mux.HandleFunc("POST /inviteStaff", api.HandleInviteStaff)
	mux.HandleFunc("POST /updateStaffRole", api.HandleUpdateStaffRole)
	mux.HandleFunc("POST /deleteStaff", api.HandleDeleteStaff)

	// QWallet — mobile endpoints
	mux.HandleFunc("GET /mobile/checkKeys", api.HandleCheckKeys)
	mux.HandleFunc("POST /mobile/registerHolderKeys", api.HandleRegisterHolderKeys)
	mux.HandleFunc("GET /mobile/getEnvelope", api.HandleGetEnvelope)
	mux.HandleFunc("GET /mobile/getHolderProfile", api.HandleMobileGetHolderProfile)
	mux.HandleFunc("GET /mobile/getCredentialsByHolder", api.HandleMobileGetCredentialsByHolder)
	mux.HandleFunc("POST /mobile/toggleFavorite", api.HandleToggleFavorite)
	mux.HandleFunc("GET /mobile/getActivity", api.HandleGetActivity)
	mux.HandleFunc("POST /mobile/generateOTP", api.HandleGenerateOTP)
	mux.HandleFunc("POST /mobile/generatePresentation", api.HandleGeneratePresentation)
	mux.HandleFunc("GET /mobile/getCatalog", api.HandleGetCatalog)
	mux.HandleFunc("POST /mobile/fetchDocument", api.HandleFetchDocument)
	mux.HandleFunc("GET /mobile/getSubscriptions", api.HandleGetMobileSubscriptions)
	mux.HandleFunc("POST /mobile/approveSubscription", api.HandleApproveSubscription)
	mux.HandleFunc("POST /mobile/rejectSubscription", api.HandleRejectSubscription)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		api.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	addr := ":" + config.ServerPort
	fmt.Printf("QChain Go backend running on %s\n", addr)
	fmt.Printf("  Network root:  %s\n", config.NetworkRoot)
	fmt.Printf("  Channel:       %s\n", config.ChannelName)
	fmt.Printf("  Chaincode:     %s\n", config.ChaincodeName)
	fmt.Printf("  IPFS host:     %s\n", config.IpfsHost)
	fmt.Printf("  PQC algo:      %s\n", pqc.SigName)
	fmt.Printf("  KEM algo:      %s (credential envelopes on IPFS, holder-held keys)\n", pqc.KemName)
	fmt.Printf("  Issuer org:    %s / %s\n", config.IssuerOrgName, config.IssuerIdentity)
	fmt.Printf("  Verifier org:  %s / %s\n", config.VerifierOrgName, config.VerifierIdentity)
	fmt.Printf("  Issuer org ID: %s\n", config.IssuerOrgID)

	log.Fatal(http.ListenAndServe(addr, corsMiddleware(mux)))
}
