package api

// mobile.go — the QWallet (holder phone app) endpoints, all under /mobile/*,
// plus /resolveSession which the verifier calls to redeem a QR/OTP token.
//
// Flow these handlers support: a holder views their wallet, marks favourites,
// fetches a document into the wallet, and approves/rejects verifier subscription
// requests. For sharing, the holder's phone signs a presentation (the disclosed
// fields plus their salts) and registers it as a short-lived OTP or QR session
// (generateOTP / generatePresentation); a verifier then submits that token to
// /resolveSession, which checks it against the chain (see verifyPresentation).
//
// Sources: holder keys, names, credential metadata and CIDs come from the
// chain; the encrypted credential body comes from IPFS; MySQL supplies the
// Emirates ID mapping, wallet flags, sessions, subscriptions and activity.

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/teamqchain/qchain-backend/config"
	"github.com/teamqchain/qchain-backend/db"
	"github.com/teamqchain/qchain-backend/ledger"
	"github.com/teamqchain/qchain-backend/pqc"
)

// Expected hex lengths of the wallet's public keys.
const (
	kemPublicKeyHexLen = 2368 // ML-KEM-768 public key, 1184 bytes
	dsaPublicKeyHexLen = 2624 // ML-DSA-44 public key, 1312 bytes
)

// GET /mobile/checkKeys?emiratesID=XXX — check if a holder has registered public
// keys (on-chain) and return them. The wallet generates and registers new keys
// only after a 200 saying none are bound, so every failure is a non-200.
func HandleCheckKeys(w http.ResponseWriter, r *http.Request) {
	emiratesID := r.URL.Query().Get("emiratesID")
	if emiratesID == "" {
		writeError(w, http.StatusBadRequest, "missing emiratesID")
		return
	}

	type checkKeysResponse struct {
		HasKemKey     bool   `json:"hasKemKey"`
		HasSigningKey bool   `json:"hasSigningKey"`
		KemPublicKey  string `json:"kemPublicKey"`
		DsaPublicKey  string `json:"dsaPublicKey"`
	}

	_, fabricHolderID, err := db.HolderByEmiratesID(emiratesID)
	if err != nil {
		if strings.Contains(err.Error(), "not registered") {
			WriteJSON(w, http.StatusOK, checkKeysResponse{})
		} else {
			writeError(w, http.StatusInternalServerError, "database error")
		}
		return
	}
	holder, err := ledger.ChainReadHolder(fabricHolderID, ledger.ViewFull)
	if errors.Is(err, ledger.ErrChainNotFound) {
		writeError(w, http.StatusInternalServerError, "holder "+fabricHolderID+" is not registered on the blockchain")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "blockchain read failed: "+err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, checkKeysResponse{
		HasKemKey:     holder.KemPublicKey != "",
		HasSigningKey: holder.DsaPublicKey != "",
		KemPublicKey:  holder.KemPublicKey,
		DsaPublicKey:  holder.DsaPublicKey,
	})
}

// POST /mobile/registerHolderKeys — binds the holder's ML-KEM and ML-DSA public
// keys on-chain (then caches them in MySQL). The backend never receives or
// persists private keys.
func HandleRegisterHolderKeys(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EmiratesID    string `json:"emiratesID"`
		KemPublicKey  string `json:"kemPublicKey"`
		DsaPublicKey  string `json:"dsaPublicKey"`
		KemPrivateKey string `json:"kemPrivateKey"`
		DsaPrivateKey string `json:"dsaPrivateKey"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.KemPrivateKey != "" || req.DsaPrivateKey != "" {
		log.Printf("SECURITY WARNING: received private key in registerHolderKeys for Emirates ID %s — ignoring", req.EmiratesID)
	}
	if req.EmiratesID == "" {
		writeError(w, http.StatusBadRequest, "missing emiratesID")
		return
	}
	if req.KemPublicKey == "" || req.DsaPublicKey == "" {
		writeError(w, http.StatusBadRequest, "missing kemPublicKey or dsaPublicKey")
		return
	}
	if _, err := hex.DecodeString(req.KemPublicKey); err != nil {
		writeError(w, http.StatusBadRequest, "invalid hex for kemPublicKey: "+err.Error())
		return
	}
	if _, err := hex.DecodeString(req.DsaPublicKey); err != nil {
		writeError(w, http.StatusBadRequest, "invalid hex for dsaPublicKey: "+err.Error())
		return
	}
	if len(req.KemPublicKey) != kemPublicKeyHexLen {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("kemPublicKey must be %d hex characters (ML-KEM-768)", kemPublicKeyHexLen))
		return
	}
	if len(req.DsaPublicKey) != dsaPublicKeyHexLen {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("dsaPublicKey must be %d hex characters (ML-DSA-44)", dsaPublicKeyHexLen))
		return
	}

	holderID, fabricHolderID, err := db.HolderByEmiratesID(req.EmiratesID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "holder not found: "+err.Error())
		return
	}

	// The chain is the source of truth for holder keys, so it is written first.
	if _, err := ledger.ChainSubmit("bindHolderKeys", fabricHolderID, req.KemPublicKey, req.DsaPublicKey); err != nil {
		log.Printf("ERROR: chaincode bindHolderKeys failed: %v", err)
		writeError(w, http.StatusInternalServerError, "chaincode bindHolderKeys failed: "+err.Error())
		return
	}
	if err := db.UpdateHolderKeys(holderID, req.KemPublicKey, req.DsaPublicKey); err != nil {
		log.Printf("DB updateHolderKeys warning (keys are bound on-chain): %v", err)
	}

	WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

// GET /mobile/getEnvelope?credentialID=CRED-XXXX — returns the encrypted
// envelope, fetched from IPFS by the CID recorded on-chain.
// FUTURE (Track H / Gap G7): Add holder authorization check (e.g. require emiratesID / session token
// and verify ownership against credentials table) before returning envelope ciphertext.
func HandleGetEnvelope(w http.ResponseWriter, r *http.Request) {
	credentialID := r.URL.Query().Get("credentialID")
	if credentialID == "" {
		writeError(w, http.StatusBadRequest, "missing credentialID")
		return
	}
	ref, err := db.CredentialRefByID(credentialID)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "credential envelope not found: credential not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	cred, _, err := ledger.ChainReadCredential(ref.FabricCredID, ledger.ViewSummary)
	if errors.Is(err, ledger.ErrChainNotFound) {
		writeError(w, http.StatusNotFound, "credential envelope not found: credential is not on the blockchain")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "blockchain read failed: "+err.Error())
		return
	}
	envelope, err := pqc.CatFromIPFS(cred.CID)
	if err != nil {
		log.Printf("ERROR: getEnvelope %s: %v", ref.CredentialID, err)
		writeError(w, http.StatusBadGateway, "IPFS read failed: "+err.Error())
		return
	}
	if !pqc.LooksLikeEnvelope(envelope) {
		writeError(w, http.StatusBadGateway, "IPFS content for this credential is not a QChain envelope")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(envelope)
}

// GET /mobile/getHolderProfile?emiratesID=XXX — basic demographic info for a
// holder (full name from the chain; email, Emirates ID, holder type, college
// from MySQL). Works even when the holder has no credentials yet.
func HandleMobileGetHolderProfile(w http.ResponseWriter, r *http.Request) {
	emiratesID := r.URL.Query().Get("emiratesID")
	if emiratesID == "" {
		writeError(w, http.StatusBadRequest, "missing emiratesID")
		return
	}
	ref, err := db.HolderRefByEmiratesID(emiratesID)
	if err != nil {
		if strings.Contains(err.Error(), "not registered") {
			writeError(w, http.StatusNotFound, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, "database error")
		}
		return
	}
	holder, err := ledger.ChainReadHolder(ref.FabricHolderID, ledger.ViewSummary)
	if errors.Is(err, ledger.ErrChainNotFound) {
		writeError(w, http.StatusNotFound, "holder "+ref.FabricHolderID+" is not registered on the blockchain")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "blockchain read failed: "+err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"success":    true,
		"fullName":   holder.FullName(),
		"email":      ref.Email,
		"emiratesID": ref.EmiratesID,
		"holderType": holderTypeDBToAPI(ref.HolderType),
		"college":    ref.College,
	})
}

// GET /mobile/getCredentialsByHolder?emiratesID=XXX — credentials in a holder's
// wallet, newest first. Metadata comes from the chain; the credential body is
// fetched separately (getEnvelope) and decrypted on the phone.
func HandleMobileGetCredentialsByHolder(w http.ResponseWriter, r *http.Request) {
	emiratesID := r.URL.Query().Get("emiratesID")
	if emiratesID == "" {
		writeError(w, http.StatusBadRequest, "missing emiratesID")
		return
	}

	refs, err := db.GetMobileCredentialRefs(emiratesID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	fabricIDs := make([]string, 0, len(refs))
	for _, ref := range refs {
		fabricIDs = append(fabricIDs, ref.FabricCredID)
	}
	snap, err := ledger.ChainReadCredentials(fabricIDs, ledger.ViewSummary)
	if err != nil {
		writeError(w, http.StatusBadGateway, "blockchain read failed: "+err.Error())
		return
	}

	type walletItem struct {
		ref  db.MobileCredentialRef
		cred *ledger.ChainCredential
	}
	var missing []string
	items := make([]walletItem, 0, len(refs))
	for _, ref := range refs {
		cred := snap.Credentials[ref.FabricCredID]
		if cred == nil {
			missing = append(missing, ref.CredentialID)
			continue
		}
		items = append(items, walletItem{ref, cred})
	}
	ledger.LogMissingOnChain("mobile/getCredentialsByHolder", missing)
	sort.SliceStable(items, func(i, j int) bool {
		return issuedAtSortKey(items[i].cred).After(issuedAtSortKey(items[j].cred))
	})

	now := time.Now()
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		c := item.cred
		issuedAt := ""
		if t, ok := ledger.FormatChainTime(c.IssuedAt); ok {
			issuedAt = t.Format(time.RFC3339)
		}
		out = append(out, map[string]any{
			"credentialID":   item.ref.CredentialID,
			"credentialType": c.CredentialType,
			"holderName":     snap.HolderOf(c).FullName(),
			"holderEID":      item.ref.HolderEID,
			"issuedBy":       item.ref.IssuerName,
			"issuedAt":       issuedAt,
			"expiryDate":     expiryOrNil(c.ExpiryDate),
			"status":         ledger.EffectiveStatus(c, now),
			"isFavorite":     item.ref.IsFavorite,
			"category":       item.ref.Category,
			"txHash":         item.ref.FabricCredID,
			"cid":            c.CID,
		})
	}
	WriteJSON(w, http.StatusOK, out)
}

// POST /mobile/toggleFavorite — pin/unpin a credential in the wallet.
func HandleToggleFavorite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HolderEID    string `json:"holderEID"`
		CredentialID string `json:"credentialID"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.HolderEID == "" {
		writeError(w, http.StatusBadRequest, "missing holderEID")
		return
	}
	if req.CredentialID == "" {
		writeError(w, http.StatusBadRequest, "missing credentialID")
		return
	}
	if err := db.ToggleFavorite(req.CredentialID, req.HolderEID); err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

// GET /mobile/getActivity?emiratesID=XXX — the holder's activity feed.
func HandleGetActivity(w http.ResponseWriter, r *http.Request) {
	emiratesID := r.URL.Query().Get("emiratesID")
	if emiratesID == "" {
		writeError(w, http.StatusBadRequest, "missing emiratesID")
		return
	}
	rows, err := db.GetMobileActivity(emiratesID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	fabricIDs := make([]string, 0, len(rows))
	for _, a := range rows {
		fabricIDs = append(fabricIDs, a.FabricCredID)
	}
	snap, err := ledger.ChainReadCredentials(fabricIDs, ledger.ViewSummary)
	if err != nil {
		writeError(w, http.StatusBadGateway, "blockchain read failed: "+err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		credentialName, _ := credentialLabel(snap, a.FabricCredID)
		out = append(out, map[string]any{
			"id":             strconv.FormatInt(a.EventID, 10),
			"type":           a.EventType,
			"credentialID":   a.CredentialID,
			"credentialName": credentialName,
			"actor":          a.ActorName,
			"timestamp":      a.CreatedAt.Format(time.RFC3339),
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "activity": out})
}

// HandleGetMobileSubscriptions returns subscription requests addressed to a
// holder for the QWallet ManageSubscriptions screen.
// GET /mobile/getSubscriptions?emiratesID=XXX
func HandleGetMobileSubscriptions(w http.ResponseWriter, r *http.Request) {
	emiratesID := r.URL.Query().Get("emiratesID")
	if emiratesID == "" {
		writeError(w, http.StatusBadRequest, "emiratesID is required")
		return
	}
	subs, err := db.GetMobileSubscriptions(emiratesID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	fabricIDs := make([]string, 0, len(subs))
	for _, s := range subs {
		fabricIDs = append(fabricIDs, s.FabricCredID)
	}
	snap, err := ledger.ChainReadCredentials(fabricIDs, ledger.ViewSummary)
	if err != nil {
		writeError(w, http.StatusBadGateway, "blockchain read failed: "+err.Error())
		return
	}
	out := make([]map[string]any, 0, len(subs))
	for _, s := range subs {
		credentialType, _ := credentialLabel(snap, s.FabricCredID)
		out = append(out, map[string]any{
			"subscriptionID": s.SubscriptionID,
			"credentialID":   s.CredentialID,
			"credentialType": credentialType,
			"verifierName":   s.VerifierName,
			"status":         s.Status,
			"createdAt":      s.CreatedAt,
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"success":       true,
		"subscriptions": out,
	})
}

// HandleApproveSubscription approves a pending subscription (status -> active).
// POST /mobile/approveSubscription  Body: { subscriptionID, emiratesID }
func HandleApproveSubscription(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SubscriptionID string `json:"subscriptionID"`
		EmiratesID     string `json:"emiratesID"`
	}
	if err := decodeBody(r, &body); err != nil || body.SubscriptionID == "" || body.EmiratesID == "" {
		writeError(w, http.StatusBadRequest, "subscriptionID and emiratesID are required")
		return
	}
	ok, err := db.UpdateSubscriptionStatus(body.SubscriptionID, body.EmiratesID, "active")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": ok})
}

// HandleRejectSubscription rejects a pending subscription (status -> rejected).
// POST /mobile/rejectSubscription  Body: { subscriptionID, emiratesID }
func HandleRejectSubscription(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SubscriptionID string `json:"subscriptionID"`
		EmiratesID     string `json:"emiratesID"`
	}
	if err := decodeBody(r, &body); err != nil || body.SubscriptionID == "" || body.EmiratesID == "" {
		writeError(w, http.StatusBadRequest, "subscriptionID and emiratesID are required")
		return
	}
	ok, err := db.UpdateSubscriptionStatus(body.SubscriptionID, body.EmiratesID, "rejected")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": ok})
}

// POST /mobile/generateOTP — create a short-lived 6-digit OTP session for manual verify.
func HandleGenerateOTP(w http.ResponseWriter, r *http.Request) {
	req, err := validatePresentationRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	holderID, err := db.CredentialHolderID(req.CredentialID)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	var otpID string
	for i := 0; i < 3; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
		otpID = fmt.Sprintf("OTP-%06d", n.Int64())
		if !db.MobileSessionExists(otpID) {
			break
		}
		otpID = ""
	}
	if otpID == "" {
		writeError(w, http.StatusInternalServerError, "unable to generate unique OTP. Please try again.")
		return
	}

	const sessionExpiresInSeconds = 120
	if err := db.InsertMobileSession(otpID, "otp", req.CredentialID, holderID, req.HiddenFields, req.DisclosedPayload, req.HolderSignature, sessionExpiresInSeconds); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	expiresAt := time.Now().In(config.MustLoadLocation("Asia/Dubai")).Add(time.Duration(sessionExpiresInSeconds) * time.Second)
	WriteJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"otp":       otpID[4:],
		"expiresAt": expiresAt.Format("2006-01-02T15:04:05"),
	})
}

// POST /mobile/generatePresentation — create a short-lived QR session ("PRES-...").
func HandleGeneratePresentation(w http.ResponseWriter, r *http.Request) {
	req, err := validatePresentationRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	holderID, err := db.CredentialHolderID(req.CredentialID)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	var presID string
	for i := 0; i < 3; i++ {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		presID = fmt.Sprintf("PRES-%x", b)
		if !db.MobileSessionExists(presID) {
			break
		}
		presID = ""
	}
	if presID == "" {
		writeError(w, http.StatusInternalServerError, "unable to generate unique session ID. Please try again.")
		return
	}

	const sessionExpiresInSeconds = 120
	if err := db.InsertMobileSession(presID, "qr", req.CredentialID, holderID, req.HiddenFields, req.DisclosedPayload, req.HolderSignature, sessionExpiresInSeconds); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	expiresAt := time.Now().In(config.MustLoadLocation("Asia/Dubai")).Add(time.Duration(sessionExpiresInSeconds) * time.Second)
	WriteJSON(w, http.StatusOK, map[string]any{
		"success":        true,
		"presentationID": presID,
		"expiresAt":      expiresAt.Format("2006-01-02T15:04:05"),
	})
}

// GET /mobile/getCatalog — the issuer/service catalog, grouped category → issuer → service.
func HandleGetCatalog(w http.ResponseWriter, r *http.Request) {
	catalogRows, err := db.GetCatalogRows()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	type serviceJSON struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	type issuerJSON struct {
		ID       string        `json:"id"`
		Name     string        `json:"name"`
		Services []serviceJSON `json:"services"`
	}
	type categoryJSON struct {
		Name    string       `json:"name"`
		Issuers []issuerJSON `json:"issuers"`
	}

	categoryMap := map[string]int{}
	categories := []categoryJSON{}

	for _, row := range catalogRows {
		catIdx, exists := categoryMap[row.Category]
		if !exists {
			catIdx = len(categories)
			categoryMap[row.Category] = catIdx
			categories = append(categories, categoryJSON{Name: row.Category, Issuers: []issuerJSON{}})
		}
		cat := &categories[catIdx]

		issuerIdx := -1
		for i, iss := range cat.Issuers {
			if iss.ID == row.IssuerID {
				issuerIdx = i
				break
			}
		}
		if issuerIdx == -1 {
			cat.Issuers = append(cat.Issuers, issuerJSON{ID: row.IssuerID, Name: row.IssuerName, Services: []serviceJSON{}})
			issuerIdx = len(cat.Issuers) - 1
		}
		if row.ServiceID.Valid {
			cat.Issuers[issuerIdx].Services = append(cat.Issuers[issuerIdx].Services, serviceJSON{
				ID:          row.ServiceID.String,
				Name:        row.ServiceName.String,
				Description: row.Description.String,
			})
		}
	}

	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "categories": categories})
}

// likePattern compiles a SQL LIKE pattern ("%" = any run, "_" = one character,
// a backslash escapes) into a case-insensitive regexp, matching MariaDB's default
// case-insensitive collation.
func likePattern(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?is)^")
	escaped := false
	for _, ch := range pattern {
		switch {
		case escaped:
			b.WriteString(regexp.QuoteMeta(string(ch)))
			escaped = false
		case ch == '\\':
			escaped = true
		case ch == '%':
			b.WriteString(".*")
		case ch == '_':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	if escaped {
		b.WriteString(regexp.QuoteMeta("\\"))
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// POST /mobile/fetchDocument — pull all of a holder's credentials from an
// issuer that match a catalog service into the wallet (sets in_wallet=1).
// The service's match pattern is applied to the ON-CHAIN credential type.
func HandleFetchDocument(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HolderEID   string `json:"holderEID"`
		IssuerID    string `json:"issuerID"`
		ServiceName string `json:"serviceName"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.HolderEID == "" {
		writeError(w, http.StatusBadRequest, "missing holderEID")
		return
	}
	if req.IssuerID == "" {
		writeError(w, http.StatusBadRequest, "missing issuerID")
		return
	}
	if req.ServiceName == "" {
		writeError(w, http.StatusBadRequest, "missing serviceName")
		return
	}
	if _, _, err := db.HolderByEmiratesID(req.HolderEID); err != nil {
		writeError(w, http.StatusBadRequest, "holder not found")
		return
	}
	var issuerCount int
	_ = db.Db.QueryRow(`SELECT COUNT(*) FROM catalog_issuers WHERE id = ?`, req.IssuerID).Scan(&issuerCount)
	if issuerCount == 0 {
		writeError(w, http.StatusBadRequest, "issuer not found")
		return
	}
	var serviceCount int
	_ = db.Db.QueryRow(`SELECT COUNT(*) FROM catalog_services WHERE issuer_id = ? AND name = ?`,
		req.IssuerID, req.ServiceName).Scan(&serviceCount)
	if serviceCount == 0 {
		writeError(w, http.StatusBadRequest, "service not found")
		return
	}

	pattern, err := likePattern(db.ServiceMatchPattern(req.IssuerID, req.ServiceName))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid catalog match pattern")
		return
	}
	candidates, err := db.HolderCredentialRefsForOrg(req.HolderEID, req.IssuerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	fabricIDs := make([]string, 0, len(candidates))
	for _, c := range candidates {
		fabricIDs = append(fabricIDs, c.FabricCredID)
	}
	snap, err := ledger.ChainReadCredentials(fabricIDs, ledger.ViewSummary)
	if err != nil {
		writeError(w, http.StatusBadGateway, "blockchain read failed: "+err.Error())
		return
	}

	// A holder may hold several credentials of the same category (e.g. two
	// Bachelor degrees); every matching one lands in the wallet.
	matched := 0
	var toAdd, missing []string
	for _, c := range candidates {
		cred := snap.Credentials[c.FabricCredID]
		if cred == nil {
			missing = append(missing, c.CredentialID)
			continue
		}
		if !pattern.MatchString(cred.CredentialType) {
			continue
		}
		matched++
		if !c.InWallet {
			toAdd = append(toAdd, c.CredentialID)
		}
	}
	ledger.LogMissingOnChain("mobile/fetchDocument", missing)

	if matched == 0 {
		WriteJSON(w, http.StatusOK, map[string]any{
			"success": false,
			"message": "Document not yet issued. Please request from the issuer.",
		})
		return
	}
	if len(toAdd) == 0 {
		WriteJSON(w, http.StatusOK, map[string]any{
			"success":         false,
			"alreadyInWallet": true,
			"message":         "This document is already in your wallet.",
		})
		return
	}
	if err := db.MarkInWallet(toAdd); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"success":         true,
		"alreadyInWallet": false,
		"message":         "Document retrieved successfully.",
	})
}

// POST /resolveSession — called by ScanToValidatePage (QR) and ManualVerifyPage (OTP).
// Frontend prepends "OTP-" to the 6-digit code before sending.
//
// Status codes matter to the portal: 404 = unknown session, 400 = expired
// session. A credential that is missing on-chain is a verification RESULT
// (200, reason NOT_FOUND), not an HTTP error. If the chain cannot be reached
// the session is kept so the verifier can retry.
func HandleResolveSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionToken string `json:"sessionToken"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.SessionToken == "" {
		writeError(w, http.StatusBadRequest, "missing sessionToken")
		return
	}

	session, err := db.GetMobileSession(req.SessionToken)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "Session not found or invalid QR code.")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if time.Now().After(session.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "Session expired. Please generate a new QR code.")
		return
	}

	fabricCredID, err := db.FabricCredIDByDisplay(session.CredentialID)
	if err != nil {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}

	// One chain read returns the credential AND its holder (whose DSA key
	// verifies the presentation) — nothing trust-relevant comes from MySQL.
	cred, holder, err := ledger.ChainReadCredential(fabricCredID, ledger.ViewFull)
	if err != nil && !errors.Is(err, ledger.ErrChainNotFound) {
		writeError(w, http.StatusBadGateway, "blockchain read failed: "+err.Error())
		return
	}
	outcome := verifyPresentation(VerifyInput{
		DisplayID:        session.CredentialID,
		FabricID:         fabricCredID,
		Cred:             cred,
		Holder:           holder,
		RawPayload:       session.DisclosedPayload,
		HolderSignature:  session.HolderSignature,
		TrustedIssuerKey: config.IssuerPubKeyHex,
		Now:              time.Now(),
	})

	// Display fields: on-chain metadata, plus email / Emirates ID (MySQL-only).
	var holderID, holderName, holderEmail, holderEID, credentialType, issuedAt, expiryDate string
	if cred != nil {
		holderID = cred.Holder
		holderName = holder.FullName()
		credentialType = cred.CredentialType
		if t, ok := ledger.FormatChainTime(cred.IssuedAt); ok {
			issuedAt = db.FormatISO(t)
		}
		expiryDate = cred.ExpiryDate
		holderEmail, holderEID, _ = db.HolderContactByFabricID(cred.Holder)
	}
	hidden := make(map[string]bool, len(session.HiddenFields))
	for _, f := range session.HiddenFields {
		hidden[f] = true
	}
	if hidden["holderName"] {
		holderName = ""
	}
	if hidden["issuedAt"] {
		issuedAt = ""
	}
	if hidden["expiryDate"] {
		expiryDate = ""
	}

	const resolveVerifiedBy = "System Verifier"
	result := "success"
	if !outcome.Verified {
		result = "failure"
	}
	db.LogVerificationToDB(session.CredentialID, fabricCredID, "VER-UOS-0001", resolveVerifiedBy,
		result, outcome.Reason, outcome.ExistsOnChain, outcome.FieldHashesValid, outcome.SignatureValid, outcome.Status)
	db.DeleteMobileSession(req.SessionToken)

	resp := map[string]any{
		"verified":       outcome.Verified,
		"credentialID":   session.CredentialID,
		"fabricCredID":   fabricCredID,
		"holderID":       holderID,
		"holderName":     holderName,
		"holderEmail":    holderEmail,
		"holderEID":      holderEID,
		"credentialType": credentialType,
		"issuer":         "University of Sharjah",
		"verifiedBy":     resolveVerifiedBy,
		"status":         outcome.Status,
		"issuedAt":       issuedAt,
		"expiryDate":     expiryDate,
		"credentialData": outcome.Disclosed,
		"checks": map[string]bool{
			"existsOnChain":        outcome.ExistsOnChain,
			"notRevoked":           outcome.NotRevoked,
			"signatureValid":       outcome.SignatureValid,
			"fieldHashesValid":     outcome.FieldHashesValid,
			"holderSignatureValid": outcome.HolderSignatureValid,
			"hashMatches":          outcome.HashMatches,
		},
	}
	if !outcome.Verified {
		resp["reason"] = outcome.Reason
	}
	WriteJSON(w, http.StatusOK, resp)
}
