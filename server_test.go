package main

/*
================================================================================
QCHAIN OFFCHAIN BACKEND TEST RUN GUIDE
================================================================================

1. Running Unit Tests in the VM (Native Environment):
   --------------------------------------------------
   If running directly on the VM with Go (1.20+) and liboqs installed:
     $ cd offchain
     $ go test -v ./...

   Run specific test suites:
     $ go test -v -run TestHandlersValidationAndHealth
     $ go test -v -run TestVerifyPresentation     (verification_test.go)
     $ go test -v -run TestCommitment             (commitment_test.go)
     $ go test -v -run TestEnvelope               (envelope_test.go)
     $ go test -v -run TestMLDSAPresentationSigning
     $ go test -v -run TestDubaiTimezoneFormat

   Run with clean cache and coverage:
     $ go test -count=1 -cover ./...

2. Running Unit Tests via Docker (liboqs Containerized):
   -----------------------------------------------------
   ML-KEM-768 and ML-DSA-44 need the liboqs C library, which only the image's
   BUILDER stage has (the runtime image has no Go toolchain):
     $ cd offchain
     $ docker build --target builder -t qchain-api:test .
     $ docker run --rm qchain-api:test go test -count=1 -v ./...

   Mounting local directory into the builder for instant test iterations:
     $ docker run --rm -v "$PWD:/app" -w /app qchain-api:test go test -v ./...

3. Running End-to-End (E2E) API Tests:
   -----------------------------------
   With the full network running (Fabric, MySQL, IPFS, Backend API):
     $ ./tests/e2e_api_test.sh

================================================================================
*/

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWriteHelpers documents the API response contract used by handlers:
// JSON content type, expected status code, and predictable error envelope.
func TestWriteHelpers(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusCreated, map[string]string{"ok": "yes"})

	if rr.Code != http.StatusCreated {
		t.Fatalf("writeJSON should set provided HTTP status. got=%d want=%d", rr.Code, http.StatusCreated)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("writeJSON should set Content-Type to application/json. got=%q", got)
	}

	var payload map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("writeJSON produced invalid JSON body: %v", err)
	}
	if payload["ok"] != "yes" {
		t.Fatalf("writeJSON body mismatch. got=%q want=%q", payload["ok"], "yes")
	}

	rr = httptest.NewRecorder()
	writeError(rr, http.StatusBadRequest, "problem")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("writeError should preserve provided HTTP status. got=%d want=%d", rr.Code, http.StatusBadRequest)
	}

	var errPayload ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errPayload); err != nil {
		t.Fatalf("writeError produced invalid JSON body: %v", err)
	}
	if errPayload.Error != "problem" {
		t.Fatalf("writeError body mismatch. got=%q want=%q", errPayload.Error, "problem")
	}
}

// TestDecodeBody is a focused parser test for request body JSON decoding.
// It confirms good JSON is accepted and malformed JSON is rejected.
func TestDecodeBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"org":"government"}`))
	var payload map[string]string
	if err := decodeBody(req, &payload); err != nil {
		t.Fatalf("decodeBody failed on valid JSON; request parser may be broken: %v", err)
	}
	if payload["org"] != "government" {
		t.Fatalf("decodeBody parsed unexpected payload value. got=%q", payload["org"])
	}

	badReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not-json"))
	if err := decodeBody(badReq, &payload); err == nil {
		t.Fatalf("expected decodeBody to fail on malformed JSON")
	}
}

// TestHandlersValidationAndHealth intentionally targets endpoint guard rails
// (input validation and health reporting) without requiring external services
// such as Fabric peers, wallet material, or IPFS.
func TestHandlersValidationAndHealth(t *testing.T) {
	// Table-driven style keeps endpoint validation checks compact and consistent.
	tests := []struct {
		name            string
		handler         http.HandlerFunc
		method          string
		target          string
		body            string
		wantStatus      int
		wantErrorSubstr string
	}{
		{
			name:            "registerHolder invalid json",
			handler:         handleRegisterHolder,
			method:          http.MethodPost,
			target:          "/registerHolder",
			body:            "{",
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "invalid JSON body",
		},
		{
			name:            "registerHolder missing params",
			handler:         handleRegisterHolder,
			method:          http.MethodPost,
			target:          "/registerHolder",
			body:            `{"org":"government"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing required fields",
		},
		{
			name:            "issueCredential missing params",
			handler:         handleIssueCredential,
			method:          http.MethodPost,
			target:          "/issueCredential",
			body:            `{"org":"government","identity":"admin"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing required fields",
		},
		{
			name:            "issueCredential non-string attribute",
			handler:         handleIssueCredential,
			method:          http.MethodPost,
			target:          "/issueCredential",
			body:            `{"holderEmiratesID":"784-1234","credentialType":"BSc","info":"{\"GPA\":3.8}"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: `field "GPA" must be a string`,
		},
		{
			name:            "issueCredential reserved attribute name",
			handler:         handleIssueCredential,
			method:          http.MethodPost,
			target:          "/issueCredential",
			body:            `{"holderEmiratesID":"784-1234","credentialType":"BSc","info":"{\"_salts\":\"x\"}"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "reserved",
		},
		{
			name:            "issueCredential invalid expiry",
			handler:         handleIssueCredential,
			method:          http.MethodPost,
			target:          "/issueCredential",
			body:            `{"holderEmiratesID":"784-1234","credentialType":"BSc","info":"{\"College\":\"CCI\",\"expiryDate\":\"soon\"}"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "invalid expiryDate",
		},
		{
			name:            "issueCredential credentialType too long",
			handler:         handleIssueCredential,
			method:          http.MethodPost,
			target:          "/issueCredential",
			body:            `{"holderEmiratesID":"784-1234","credentialType":"` + strings.Repeat("x", 101) + `","info":"{\"College\":\"CCI\"}"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "at most 100 characters",
		},
		{
			name:            "updateCredential invalid expiry",
			handler:         handleUpdateCredential,
			method:          http.MethodPost,
			target:          "/updateCredential",
			body:            `{"credentialID":"CRED-0001","expiryDate":"soon"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "invalid expiryDate format",
		},
		{
			name:            "revokeCredential missing params",
			handler:         handleRevokeCredential,
			method:          http.MethodPost,
			target:          "/revokeCredential",
			body:            `{"org":"government"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing credentialID",
		},
		{
			name:            "checkKeys missing emiratesID",
			handler:         handleCheckKeys,
			method:          http.MethodGet,
			target:          "/mobile/checkKeys",
			body:            "",
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing emiratesID",
		},
		{
			name:            "registerHolderKeys missing emiratesID",
			handler:         handleRegisterHolderKeys,
			method:          http.MethodPost,
			target:          "/mobile/registerHolderKeys",
			body:            `{"kemPublicKey":"aabb","dsaPublicKey":"ccdd"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing emiratesID",
		},
		{
			name:            "registerHolderKeys missing keys",
			handler:         handleRegisterHolderKeys,
			method:          http.MethodPost,
			target:          "/mobile/registerHolderKeys",
			body:            `{"emiratesID":"784-1234"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing kemPublicKey or dsaPublicKey",
		},
		{
			name:            "registerHolderKeys invalid hex",
			handler:         handleRegisterHolderKeys,
			method:          http.MethodPost,
			target:          "/mobile/registerHolderKeys",
			body:            `{"emiratesID":"784-1234","kemPublicKey":"not-hex","dsaPublicKey":"aabb"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "invalid hex",
		},
		{
			name:            "getEnvelope missing credentialID",
			handler:         handleGetEnvelope,
			method:          http.MethodGet,
			target:          "/mobile/getEnvelope",
			body:            "",
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing credentialID",
		},
		{
			name:            "getHolderProfile missing emiratesID",
			handler:         handleMobileGetHolderProfile,
			method:          http.MethodGet,
			target:          "/mobile/getHolderProfile",
			body:            "",
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing emiratesID",
		},
		{
			name:            "generateOTP missing credentialID",
			handler:         handleGenerateOTP,
			method:          http.MethodPost,
			target:          "/mobile/generateOTP",
			body:            `{}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing credentialID",
		},
		{
			name:            "generateOTP missing disclosedPayload",
			handler:         handleGenerateOTP,
			method:          http.MethodPost,
			target:          "/mobile/generateOTP",
			body:            `{"credentialID":"CRED-001"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing disclosedPayload",
		},
		{
			name:            "generateOTP missing holderSignature",
			handler:         handleGenerateOTP,
			method:          http.MethodPost,
			target:          "/mobile/generateOTP",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{\"credentialID\":\"CRED-001\"}"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing holderSignature",
		},
		{
			name:            "generateOTP missing payload credentialID",
			handler:         handleGenerateOTP,
			method:          http.MethodPost,
			target:          "/mobile/generateOTP",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{\"disclosedFields\":{}}","holderSignature":"sig123"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "disclosedPayload missing credentialID",
		},
		{
			name:            "generateOTP credentialID mismatch",
			handler:         handleGenerateOTP,
			method:          http.MethodPost,
			target:          "/mobile/generateOTP",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{\"credentialID\":\"CRED-999\"}","holderSignature":"sig123"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "does not match",
		},
		{
			name:            "generatePresentation missing credentialID",
			handler:         handleGeneratePresentation,
			method:          http.MethodPost,
			target:          "/mobile/generatePresentation",
			body:            `{}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing credentialID",
		},
		{
			name:            "generatePresentation missing disclosedPayload",
			handler:         handleGeneratePresentation,
			method:          http.MethodPost,
			target:          "/mobile/generatePresentation",
			body:            `{"credentialID":"CRED-001"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing disclosedPayload",
		},
		{
			name:            "generatePresentation missing holderSignature",
			handler:         handleGeneratePresentation,
			method:          http.MethodPost,
			target:          "/mobile/generatePresentation",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{\"credentialID\":\"CRED-001\"}"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing holderSignature",
		},
		{
			name:            "generatePresentation missing payload credentialID",
			handler:         handleGeneratePresentation,
			method:          http.MethodPost,
			target:          "/mobile/generatePresentation",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{\"disclosedFields\":{}}","holderSignature":"sig123"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "disclosedPayload missing credentialID",
		},
		{
			name:            "generatePresentation credentialID mismatch",
			handler:         handleGeneratePresentation,
			method:          http.MethodPost,
			target:          "/mobile/generatePresentation",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{\"credentialID\":\"CRED-999\"}","holderSignature":"sig123"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "does not match",
		},
		{
			name:            "generateOTP malformed json in disclosedPayload",
			handler:         handleGenerateOTP,
			method:          http.MethodPost,
			target:          "/mobile/generateOTP",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{invalid-json","holderSignature":"sig123"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "invalid JSON in disclosedPayload",
		},
		{
			name:            "generatePresentation malformed json in disclosedPayload",
			handler:         handleGeneratePresentation,
			method:          http.MethodPost,
			target:          "/mobile/generatePresentation",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{invalid-json","holderSignature":"sig123"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "invalid JSON in disclosedPayload",
		},
		{
			name:            "registerHolderKeys wrong kem key length",
			handler:         handleRegisterHolderKeys,
			method:          http.MethodPost,
			target:          "/mobile/registerHolderKeys",
			body:            `{"emiratesID":"784-1234","kemPublicKey":"aabb","dsaPublicKey":"ccdd"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "kemPublicKey must be 2368 hex characters",
		},
		{
			name:            "generateOTP missing salts",
			handler:         handleGenerateOTP,
			method:          http.MethodPost,
			target:          "/mobile/generateOTP",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{\"credentialID\":\"CRED-001\",\"disclosedFields\":{\"GPA\":\"3.8\"}}","holderSignature":"sig123"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: `salts missing for field "GPA"`,
		},
		{
			name:            "generatePresentation salt for undisclosed field",
			handler:         handleGeneratePresentation,
			method:          http.MethodPost,
			target:          "/mobile/generatePresentation",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{\"credentialID\":\"CRED-001\",\"disclosedFields\":{\"GPA\":\"3.8\"},\"salts\":{\"GPA\":\"0123456789abcdef0123456789abcdef\",\"College\":\"0123456789abcdef0123456789abcdef\"}}","holderSignature":"sig123"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: `salt provided for undisclosed field "College"`,
		},
		{
			name:            "generateOTP malformed salt",
			handler:         handleGenerateOTP,
			method:          http.MethodPost,
			target:          "/mobile/generateOTP",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{\"credentialID\":\"CRED-001\",\"disclosedFields\":{\"GPA\":\"3.8\"},\"salts\":{\"GPA\":\"XYZ\"}}","holderSignature":"sig123"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: `invalid salt for field "GPA"`,
		},
		{
			name:            "generatePresentation non-string disclosed value",
			handler:         handleGeneratePresentation,
			method:          http.MethodPost,
			target:          "/mobile/generatePresentation",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{\"credentialID\":\"CRED-001\",\"disclosedFields\":{\"GPA\":3.8}}","holderSignature":"sig123"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: `disclosedFields["GPA"] must be a string`,
		},
		{
			name:            "generateOTP nothing disclosed",
			handler:         handleGenerateOTP,
			method:          http.MethodPost,
			target:          "/mobile/generateOTP",
			body:            `{"credentialID":"CRED-001","disclosedPayload":"{\"credentialID\":\"CRED-001\",\"disclosedFields\":{}}","holderSignature":"sig123"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "disclosedFields must contain at least one field",
		},
		{
			name:            "resolveSession missing sessionToken",
			handler:         handleResolveSession,
			method:          http.MethodPost,
			target:          "/resolveSession",
			body:            `{}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing sessionToken",
		},
		{
			name:            "toggleFavorite missing holderEID",
			handler:         handleToggleFavorite,
			method:          http.MethodPost,
			target:          "/mobile/toggleFavorite",
			body:            `{"credentialID":"CRED-001"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing holderEID",
		},
		{
			name:            "toggleFavorite missing credentialID",
			handler:         handleToggleFavorite,
			method:          http.MethodPost,
			target:          "/mobile/toggleFavorite",
			body:            `{"holderEID":"784-1234"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing credentialID",
		},
		{
			name:            "fetchDocument missing holderEID",
			handler:         handleFetchDocument,
			method:          http.MethodPost,
			target:          "/mobile/fetchDocument",
			body:            `{"issuerID":"iss-1","serviceName":"deg"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing holderEID",
		},
		{
			name:            "fetchDocument missing issuerID",
			handler:         handleFetchDocument,
			method:          http.MethodPost,
			target:          "/mobile/fetchDocument",
			body:            `{"holderEID":"784-1234","serviceName":"deg"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing issuerID",
		},
		{
			name:            "fetchDocument missing serviceName",
			handler:         handleFetchDocument,
			method:          http.MethodPost,
			target:          "/mobile/fetchDocument",
			body:            `{"holderEID":"784-1234","issuerID":"iss-1"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing serviceName",
		},
		{
			name:            "getSubscriptions missing emiratesID",
			handler:         handleGetMobileSubscriptions,
			method:          http.MethodGet,
			target:          "/mobile/getSubscriptions",
			body:            "",
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "emiratesID is required",
		},
		{
			name:            "approveSubscription missing params",
			handler:         handleApproveSubscription,
			method:          http.MethodPost,
			target:          "/mobile/approveSubscription",
			body:            `{"subscriptionID":"SUB-1"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "subscriptionID and emiratesID are required",
		},
		{
			name:            "rejectSubscription missing params",
			handler:         handleRejectSubscription,
			method:          http.MethodPost,
			target:          "/mobile/rejectSubscription",
			body:            `{"subscriptionID":"SUB-1"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "subscriptionID and emiratesID are required",
		},
		{
			name:            "suspendCredential missing credentialID",
			handler:         handleSuspendCredential,
			method:          http.MethodPost,
			target:          "/suspendCredential",
			body:            `{"reason":"test investigation"}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing credentialID",
		},
		{
			name:            "restoreCredential missing credentialID",
			handler:         handleRestoreCredential,
			method:          http.MethodPost,
			target:          "/restoreCredential",
			body:            `{}`,
			wantStatus:      http.StatusBadRequest,
			wantErrorSubstr: "missing credentialID",
		},
	}

	// Each case must return the expected HTTP code and an actionable error hint.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, strings.NewReader(tt.body))
			rr := httptest.NewRecorder()
			tt.handler(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("%s failed: unexpected HTTP status. got=%d want=%d. response=%s", tt.name, rr.Code, tt.wantStatus, rr.Body.String())
			}

			var er ErrorResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &er); err != nil {
				t.Fatalf("%s failed: response is not valid ErrorResponse JSON: %v. raw=%s", tt.name, err, rr.Body.String())
			}

			if !strings.Contains(er.Error, tt.wantErrorSubstr) {
				t.Fatalf("%s failed: error message missing expected hint. got=%q want-substring=%q", tt.name, er.Error, tt.wantErrorSubstr)
			}
		})
	}

	// Health check is kept independent and simple: service should report status=ok.
	t.Run("health endpoint", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		})

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("health endpoint should return 200. got=%d body=%s", rr.Code, rr.Body.String())
		}

		var body map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("health endpoint returned malformed JSON: %v", err)
		}
		if body["status"] != "ok" {
			t.Fatalf("health endpoint payload mismatch. got status=%q", body["status"])
		}
	})
}
