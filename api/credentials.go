package api

// credentials.go — HTTP handlers for the credential lifecycle.
//
// Covers: register a holder, issue a credential (salt + hash + encrypt + IPFS +
// sign + commit to Fabric), revoke / suspend / restore, update the expiry or
// holder email, and the portal read endpoints.
//
// Source of truth: the chain for every field it holds (read via chain.go), IPFS
// for the encrypted credential body, MySQL only for what exists nowhere else
// (display IDs, holder email / Emirates ID, issuing staff member, event trail).
// Writes go to the chain first; MySQL's cache columns are updated after a
// successful chain write.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/teamqchain/qchain-backend/config"
	"github.com/teamqchain/qchain-backend/db"
	"github.com/teamqchain/qchain-backend/ledger"
	"github.com/teamqchain/qchain-backend/pqc"
)

// maxCredentialTypeLength matches credentials.credential_type VARCHAR(100);
// checked before the chain write so a long type can't orphan a credential.
const maxCredentialTypeLength = 100

// ─────────────────────────────────────────────
//  REQUEST TYPES (JSON bodies the frontend POSTs)
// ─────────────────────────────────────────────

// RegisterHolderRequest — setup script only; not called from any frontend.
// holderID is always server-generated (see nextHolderID) and is not a
// request field — a caller can never choose or collide with an existing one.
type RegisterHolderRequest struct {
	EmiratesID string `json:"emiratesID"` // stored in MySQL holders table
	FirstName  string `json:"firstName"`
	LastName   string `json:"lastName"`
	Email      string `json:"email"`   // optional; MySQL-only, UNIQUE if set
	College    string `json:"college"` // optional; MySQL-only
}

// IssueCredentialRequest — called by QPortal issuer screen (Step 5 button).
type IssueCredentialRequest struct {
	HolderEmiratesID string `json:"holderEmiratesID"` // lookup key into MySQL holders table
	CredentialType   string `json:"credentialType"`   // human-readable type, e.g. "BSc Computer Science"
	Info             string `json:"info"`             // JSON object string: field name → string value (+ optional expiryDate)
}

// RevokeCredentialRequest — called by QPortal issuer revoke/suspend screen.
type RevokeCredentialRequest struct {
	CredentialID string `json:"credentialID"` // display ID e.g. "CRED-0001"
}

// SuspendCredentialRequest — temporary, reversible status change.
type SuspendCredentialRequest struct {
	CredentialID string `json:"credentialID"`
	Reason       string `json:"reason"`
}

// RestoreCredentialRequest — restore a suspended credential back to active.
type RestoreCredentialRequest struct {
	CredentialID string `json:"credentialID"`
}

// ─────────────────────────────────────────────
//  WRITE HANDLERS
// ─────────────────────────────────────────────

// POST /registerHolder — used by setup script only; not called from any frontend.
func HandleRegisterHolder(w http.ResponseWriter, r *http.Request) {
	var req RegisterHolderRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.FirstName == "" || req.LastName == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: firstName, lastName")
		return
	}

	holderID, err := db.NextHolderID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate holder ID: "+err.Error())
		return
	}

	result, err := ledger.ChainSubmit("registerHolder", holderID, req.FirstName, req.LastName)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already registered") {
			status = http.StatusConflict
		}
		writeError(w, status, "chaincode registerHolder failed: "+err.Error())
		return
	}

	// Persist to MySQL (optional — logs warning if DB not configured)
	if req.EmiratesID != "" {
		if dbErr := db.InsertHolder(holderID, req.EmiratesID, req.FirstName, req.LastName, req.Email, req.College); dbErr != nil {
			log.Printf("DB insertHolder warning: %v", dbErr)
		}
	}

	var parsed any
	_ = json.Unmarshal(result, &parsed)
	WriteJSON(w, http.StatusOK, map[string]any{
		"holderID": holderID,
		"result":   parsed,
	})
}

// POST /issueCredential — called by QPortal issuer screen.
//
// 1. validate the attributes and lift out expiryDate (metadata, not a field)
// 2. read the holder's ML-KEM key from the chain
// 3. salt + hash every field; encrypt fields + salts to the holder
// 4. upload the envelope to IPFS (mandatory — its CID is signed)
// 5. sign the commitment and write the credential record to the chain
// 6. cache a copy in MySQL and record the issuance event
func HandleIssueCredential(w http.ResponseWriter, r *http.Request) {
	var req IssueCredentialRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	credentialType := strings.TrimSpace(req.CredentialType)
	if req.HolderEmiratesID == "" || credentialType == "" || req.Info == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: holderEmiratesID, credentialType, info")
		return
	}
	if len(credentialType) > maxCredentialTypeLength {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("credentialType must be at most %d characters", maxCredentialTypeLength))
		return
	}
	attrs, expiry, err := pqc.NormalizeIssueAttributes(req.Info)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid info: "+err.Error())
		return
	}

	// 1. Emirates ID → holder (MySQL-only mapping), then the holder's key (chain).
	holderID, fabricHolderID, err := db.HolderByEmiratesID(req.HolderEmiratesID)
	if err != nil {
		writeError(w, http.StatusNotFound, "holder not found — Emirates ID not registered: "+err.Error())
		return
	}
	holder, err := ledger.ChainReadHolder(fabricHolderID, ledger.ViewFull)
	if errors.Is(err, ledger.ErrChainNotFound) {
		writeError(w, http.StatusBadRequest, "holder "+fabricHolderID+" is not registered on the blockchain")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "blockchain read failed: "+err.Error())
		return
	}
	if holder.KemPublicKey == "" {
		writeError(w, http.StatusBadRequest, "Holder has not activated their wallet (no ML-KEM public key registered)")
		return
	}

	// 2. Salted field hashes (chain) + salts (holder only, inside the envelope).
	salts, fieldHashes, err := pqc.CommitAttributes(attrs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "field hashing failed: "+err.Error())
		return
	}
	envelope, err := pqc.SealCredentialEnvelope(attrs, salts, holder.KemPublicKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "off-chain encryption failed: "+err.Error())
		return
	}

	// 3. IPFS is the only home of the credential body, so issuance stops here
	// if the upload fails.
	cid, err := pqc.UploadJSONToIPFS(envelope)
	if err != nil {
		log.Printf("ERROR: issueCredential: %v", err)
		writeError(w, http.StatusBadGateway, "IPFS upload failed: "+err.Error())
		return
	}

	// 4. Sign the commitment and write it to the chain. Dubai local time, like
	// every other timestamp this API returns — the chaincode's skew check
	// compares absolute instants, so any timezone offset works correctly.
	issuedAtTime := time.Now().In(config.MustLoadLocation("Asia/Dubai")).Truncate(time.Second)
	commitment := pqc.CredentialCommitment{
		HolderID:       fabricHolderID,
		CredentialType: credentialType,
		IssuedAt:       issuedAtTime.Format(time.RFC3339),
		IssuerOrgID:    config.IssuerOrgID,
		ExpiryDate:     expiry,
		CID:            cid,
		FieldHashes:    fieldHashes,
	}
	credentialHash, signature, err := pqc.SignCommitment(commitment, config.IssuerPrivKeyHex)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "PQC sign failed: "+err.Error())
		return
	}
	fieldHashesJSON, err := json.Marshal(fieldHashes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "field hash marshal failed: "+err.Error())
		return
	}
	result, err := ledger.ChainSubmit("issueCredential",
		fabricHolderID, credentialType, commitment.IssuedAt, expiry, config.IssuerOrgID, cid, string(fieldHashesJSON), credentialHash, signature, config.IssuerPubKeyHex,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "chaincode issueCredential failed: "+err.Error())
		return
	}
	var chainResp struct {
		CredentialID string `json:"credentialID"`
	}
	if err := json.Unmarshal(result, &chainResp); err != nil || chainResp.CredentialID == "" {
		writeError(w, http.StatusInternalServerError, "chaincode did not return a valid credential ID")
		return
	}
	fabricCredID := chainResp.CredentialID

	// 5. Display ID + MySQL copy. The credential already exists on-chain, so a
	// failure here is reported (with the Fabric ID) rather than swallowed.
	displayCredID := db.NextDisplayCredID()
	var expirySQL sql.NullTime
	if t, ok := ledger.ExpiryAsTime(expiry); ok {
		expirySQL = sql.NullTime{Time: t, Valid: true}
	}
	if dbErr := db.InsertCredential(db.CredentialInsert{
		CredentialID:   displayCredID,
		FabricCredID:   fabricCredID,
		HolderID:       holderID,
		CredentialType: credentialType,
		CredentialHash: credentialHash,
		Signature:      signature,
		PublicKey:      config.IssuerPubKeyHex,
		IPFSCID:        cid,
		CredentialData: string(envelope),
		EncVersion:     pqc.EnvelopeVersion,
		IssuedAt:       issuedAtTime,
		ExpiryDate:     expirySQL,
	}); dbErr != nil {
		log.Printf("ERROR: credential %s is on-chain but the MySQL insert failed: %v", fabricCredID, dbErr)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf(
			"credential %s was written to the blockchain but could not be saved to the database: %v", fabricCredID, dbErr))
		return
	}
	db.InsertCredentialEvent(displayCredID, "issued", config.IssuerActorID, config.IssuerActorName, "")
	db.InsertAuditLog("issued", fmt.Sprintf("Credential %s issued to holder %s", displayCredID, holderID), config.IssuerActorName, "Issuer Admin", r.RemoteAddr)

	var expiryOut any
	if expiry != "" {
		expiryOut = expiry
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"success":        true,
		"credentialID":   displayCredID,
		"fabricCredID":   fabricCredID,
		"holderID":       holderID,
		"credentialHash": credentialHash,
		"ipfsCID":        cid,
		"issuedAt":       db.FormatISO(issuedAtTime),
		"expiryDate":     expiryOut,
	})
}

// loadCredentialForWrite resolves a display ID and reads the credential's
// current on-chain record. On failure it writes the HTTP error and returns
// ok=false.
func loadCredentialForWrite(w http.ResponseWriter, displayID, view string) (fabricID string, cred *ledger.ChainCredential, holder *ledger.ChainHolder, ok bool) {
	fabricID, err := db.FabricCredIDByDisplay(displayID)
	if err != nil {
		writeError(w, http.StatusNotFound, "credential not found: "+err.Error())
		return "", nil, nil, false
	}
	cred, holder, err = ledger.ChainReadCredential(fabricID, view)
	if errors.Is(err, ledger.ErrChainNotFound) {
		writeError(w, http.StatusNotFound, "credential not found on the blockchain")
		return "", nil, nil, false
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "blockchain read failed: "+err.Error())
		return "", nil, nil, false
	}
	return fabricID, cred, holder, true
}

// raiseSubscriptionAlert notifies subscribed verifiers of a status change,
// snapshotting the credential type and holder name from the chain.
func raiseSubscriptionAlert(displayID string, cred *ledger.ChainCredential, holder *ledger.ChainHolder, severity, description string) {
	hasSub, err := db.ActiveSubscriptionExists(displayID)
	if err != nil || !hasSub {
		return
	}
	holderID, err := db.CredentialHolderID(displayID)
	if err != nil {
		log.Printf("raiseSubscriptionAlert: holder lookup for %s failed: %v", displayID, err)
		return
	}
	db.InsertAlertForCredential(displayID, cred.CredentialType, holderID, holder.FullName(), severity, description)
}

// POST /revokeCredential — called by QPortal issuer revoke screen.
func HandleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	var req RevokeCredentialRequest
	if err := decodeBody(r, &req); err != nil || req.CredentialID == "" {
		writeError(w, http.StatusBadRequest, "missing credentialID")
		return
	}
	fabricCredID, cred, holder, ok := loadCredentialForWrite(w, req.CredentialID, ledger.ViewSummary)
	if !ok {
		return
	}
	if cred.Status == "revoked" {
		writeError(w, http.StatusBadRequest, "credential already revoked")
		return
	}

	result, err := ledger.ChainSubmit("revokeCredential", fabricCredID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "chaincode revokeCredential failed: "+err.Error())
		return
	}

	if dbErr := db.MarkCredentialRevoked(req.CredentialID); dbErr != nil {
		log.Printf("DB markCredentialRevoked warning: %v", dbErr)
	}
	raiseSubscriptionAlert(req.CredentialID, cred, holder, "revoked", "Credential has been revoked.")
	db.InsertCredentialEvent(req.CredentialID, "revoked", config.IssuerActorID, config.IssuerActorName, "")
	db.InsertAuditLog("revoked", fmt.Sprintf("Credential %s revoked", req.CredentialID), config.IssuerActorName, "Issuer Admin", r.RemoteAddr)

	var parsed any
	_ = json.Unmarshal(result, &parsed)
	WriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"message":      "Credential revoked successfully",
		"credentialID": req.CredentialID,
		"result":       parsed,
	})
}

// ─── SUSPEND ─────────────────────────────────────────────────────────────────

// POST /suspendCredential
func HandleSuspendCredential(w http.ResponseWriter, r *http.Request) {
	var req SuspendCredentialRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.CredentialID == "" {
		writeError(w, http.StatusBadRequest, "missing credentialID")
		return
	}
	fabricCredID, cred, holder, ok := loadCredentialForWrite(w, req.CredentialID, ledger.ViewSummary)
	if !ok {
		return
	}
	switch ledger.EffectiveStatus(cred, time.Now()) {
	case "suspended":
		writeError(w, http.StatusBadRequest, "credential already suspended")
		return
	case "revoked":
		writeError(w, http.StatusBadRequest, "cannot suspend revoked credential")
		return
	case "expired":
		writeError(w, http.StatusBadRequest, "cannot suspend expired credential")
		return
	}

	if _, err := ledger.ChainSubmit("suspendCredential", fabricCredID, req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, "chaincode error: "+err.Error())
		return
	}

	if dbErr := db.MarkCredentialSuspended(req.CredentialID, req.Reason); dbErr != nil {
		log.Printf("DB markCredentialSuspended warning: %v", dbErr)
	}
	// Surface the change on the verifier's Alerts page / dashboard.
	raiseSubscriptionAlert(req.CredentialID, cred, holder, "suspended",
		fmt.Sprintf("Credential has been suspended. Reason: %s", req.Reason))
	db.InsertCredentialEvent(req.CredentialID, "suspended", config.IssuerActorID, config.IssuerActorName, req.Reason)
	db.InsertAuditLog("suspended", fmt.Sprintf("Credential %s suspended. Reason: %s", req.CredentialID, req.Reason), config.IssuerActorName, "Issuer Admin", r.RemoteAddr)

	WriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"message":      "Credential suspended successfully",
		"credentialID": req.CredentialID,
	})
}

// ─── RESTORE ─────────────────────────────────────────────────────────────────

// POST /restoreCredential — DEVIATION from V3 doc: only restores from "suspended".
// Revoked credentials are permanent (security policy).
func HandleRestoreCredential(w http.ResponseWriter, r *http.Request) {
	var req RestoreCredentialRequest
	if err := decodeBody(r, &req); err != nil || req.CredentialID == "" {
		writeError(w, http.StatusBadRequest, "missing credentialID")
		return
	}
	fabricCredID, cred, _, ok := loadCredentialForWrite(w, req.CredentialID, ledger.ViewSummary)
	if !ok {
		return
	}
	switch ledger.EffectiveStatus(cred, time.Now()) {
	case "active":
		writeError(w, http.StatusBadRequest, "credential already active")
		return
	case "revoked":
		writeError(w, http.StatusBadRequest, "cannot restore revoked credential")
		return
	case "expired":
		writeError(w, http.StatusBadRequest, "cannot restore expired credential")
		return
	}

	if _, err := ledger.ChainSubmit("restoreCredential", fabricCredID); err != nil {
		writeError(w, http.StatusInternalServerError, "chaincode error: "+err.Error())
		return
	}

	if dbErr := db.MarkCredentialRestored(req.CredentialID); dbErr != nil {
		log.Printf("DB markCredentialRestored warning: %v", dbErr)
	}
	db.InsertCredentialEvent(req.CredentialID, "restored", config.IssuerActorID, config.IssuerActorName, "")
	db.InsertAuditLog("restored", fmt.Sprintf("Credential %s restored to active", req.CredentialID), config.IssuerActorName, "Issuer Admin", r.RemoteAddr)

	WriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"message":      "Credential restored successfully",
		"credentialID": req.CredentialID,
	})
}

// POST /updateCredential — edit holder email and/or expiry on a non-revoked
// credential. Expiry is part of the signed commitment, so a changed expiry is
// re-signed and written on-chain (updateExpiry). The portal resends the
// current expiry with every email edit; an unchanged expiry is not re-signed.
func HandleUpdateCredential(w http.ResponseWriter, r *http.Request) {
	// *string (pointer to string) lets us tell "field omitted" (nil) apart from
	// "field set to empty string" — important because "" clears the expiry.
	var req struct {
		CredentialID string  `json:"credentialID"`
		HolderEmail  *string `json:"holderEmail"`
		ExpiryDate   *string `json:"expiryDate"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.CredentialID == "" {
		writeError(w, http.StatusBadRequest, "missing credentialID")
		return
	}
	var newExpiry *string
	if req.ExpiryDate != nil {
		e, err := pqc.ParseExpiryDate(*req.ExpiryDate)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expiryDate format: "+err.Error())
			return
		}
		newExpiry = &e
	}

	fabricCredID, cred, _, ok := loadCredentialForWrite(w, req.CredentialID, ledger.ViewFull)
	if !ok {
		return
	}
	if cred.Status == "revoked" {
		writeError(w, http.StatusBadRequest, "cannot update a revoked credential")
		return
	}

	if newExpiry != nil && *newExpiry != cred.ExpiryDate {
		commitment := pqc.CommitmentFromChain(cred)
		commitment.ExpiryDate = *newExpiry
		credentialHash, signature, err := pqc.SignCommitment(commitment, config.IssuerPrivKeyHex)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "PQC sign failed: "+err.Error())
			return
		}
		if _, err := ledger.ChainSubmit("updateExpiry", fabricCredID, *newExpiry, credentialHash, signature, config.IssuerPubKeyHex); err != nil {
			writeError(w, http.StatusInternalServerError, "chaincode updateExpiry failed: "+err.Error())
			return
		}
		var expiryTime *time.Time
		if t, ok := ledger.ExpiryAsTime(*newExpiry); ok {
			expiryTime = &t
		}
		if dbErr := db.UpdateCredentialCommitment(req.CredentialID, expiryTime, credentialHash, signature); dbErr != nil {
			log.Printf("DB updateCredentialCommitment warning: %v", dbErr)
		}
		db.InsertAuditLog("settings_changed",
			fmt.Sprintf("Credential %s expiry changed from %s to %s (re-signed on-chain)",
				req.CredentialID, firstNonEmpty(cred.ExpiryDate, "none"), firstNonEmpty(*newExpiry, "none")), config.IssuerActorName, "Issuer Admin", r.RemoteAddr)
	}

	if req.HolderEmail != nil {
		if err := db.UpdateHolderEmail(req.CredentialID, *req.HolderEmail); err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "credentialID": req.CredentialID})
}

// ─────────────────────────────────────────────
//  READ HANDLERS
// ─────────────────────────────────────────────

// portalCredential is one credential as the portal lists it: MySQL refs merged
// with the on-chain record.
type portalCredential struct {
	Ref    db.CredentialRef
	Cred   *ledger.ChainCredential
	Holder *ledger.ChainHolder
	Status string // effective status
}

// issuedAtSortKey orders credentials newest first; unparseable times sort last.
func issuedAtSortKey(c *ledger.ChainCredential) time.Time {
	t, _ := ledger.FormatChainTime(c.IssuedAt)
	return t
}

// GET /getAllCredentials?status=active&page=1&limit=25
func HandleGetAllCredentials(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := parsePositiveInt(q.Get("page"), 1)
	limitStr := q.Get("limit")
	limit := 25
	if limitStr != "" {
		v, err := strconv.Atoi(limitStr)
		if err == nil {
			if v == 0 {
				writeError(w, http.StatusBadRequest, "limit must be >= 1")
				return
			}
			if v < 0 {
				v = 25
			}
			if v > 100 {
				v = 100
			}
			limit = v
		}
	}

	status := q.Get("status")
	if !validCredentialStatus(status) {
		status = ""
	}

	refs, err := db.ListCredentialRefs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DB query failed: "+err.Error())
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

	now := time.Now()
	var missing []string
	items := make([]portalCredential, 0, len(refs))
	for _, ref := range refs {
		cred := snap.Credentials[ref.FabricCredID]
		if cred == nil {
			missing = append(missing, ref.CredentialID)
			continue
		}
		st := ledger.EffectiveStatus(cred, now)
		if status != "" && st != status {
			continue
		}
		items = append(items, portalCredential{Ref: ref, Cred: cred, Holder: snap.HolderOf(cred), Status: st})
	}
	ledger.LogMissingOnChain("getAllCredentials", missing)
	sort.SliceStable(items, func(i, j int) bool {
		ti, tj := issuedAtSortKey(items[i].Cred), issuedAtSortKey(items[j].Cred)
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return items[i].Ref.CredentialID > items[j].Ref.CredentialID
	})

	total := len(items)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	out := make([]map[string]any, 0, end-start)
	for _, item := range items[start:end] {
		out = append(out, credentialToJSON(item))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"credentials": out,
		"total":       total,
		"page":        page,
		"limit":       limit,
	})
}

// GET /getCredentialDetail?credentialID=CRED-0001
func HandleGetCredentialDetail(w http.ResponseWriter, r *http.Request) {
	credentialID := r.URL.Query().Get("credentialID")
	if credentialID == "" {
		writeError(w, http.StatusBadRequest, "missing credentialID")
		return
	}
	ref, err := db.CredentialRefByID(credentialID)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	cred, holder, err := ledger.ChainReadCredential(ref.FabricCredID, ledger.ViewSummary)
	if errors.Is(err, ledger.ErrChainNotFound) {
		ledger.LogMissingOnChain("getCredentialDetail", []string{ref.CredentialID})
		writeError(w, http.StatusNotFound, "credential not found on the blockchain")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "blockchain read failed: "+err.Error())
		return
	}

	trail, err := db.GetCredentialAuditTrail(ref.CredentialID)
	if err != nil {
		log.Printf("getCredentialAuditTrail warning: %v", err)
	}
	trailJSON := make([]map[string]any, 0, len(trail))
	for _, t := range trail {
		var note any
		if t.Notes.Valid {
			note = t.Notes.String
		}
		trailJSON = append(trailJSON, map[string]any{
			"action":      t.Action,
			"performedBy": t.PerformedBy,
			"date":        db.FormatDateDisplay(t.OccurredAt),
			"note":        note,
		})
	}

	out := credentialToJSON(portalCredential{Ref: ref, Cred: cred, Holder: holder, Status: ledger.EffectiveStatus(cred, time.Now())})
	WriteJSON(w, http.StatusOK, map[string]any{
		"credentialID":   out["credentialID"],
		"credentialType": out["credentialType"],
		"holderName":     out["holderName"],
		"holderEmail":    out["holderEmail"],
		"holderEID":      out["holderEID"],
		"holderID":       out["holderID"],
		"issuedAt":       out["issuedAt"],
		"issuedBy":       out["issuedBy"],
		"status":         out["status"],
		"expiryDate":     out["expiryDate"],
		"auditTrail":     trailJSON,
	})
}

// ─────────────────────────────────────────────
//  SHARED CREDENTIAL HELPERS
// ─────────────────────────────────────────────

// expiryOrNil returns a YYYY-MM-DD expiry, or nil (JSON null) when there is none.
func expiryOrNil(expiry string) any {
	if expiry == "" {
		return nil
	}
	return expiry
}

// credentialToJSON shapes a portal credential into the V3 credential object.
// Used by /getAllCredentials and /getCredentialDetail.
func credentialToJSON(p portalCredential) map[string]any {
	issuedISO := ""
	if t, ok := ledger.FormatChainTime(p.Cred.IssuedAt); ok {
		issuedISO = db.FormatISO(t)
	}
	return map[string]any{
		"credentialID":   p.Ref.CredentialID,
		"credentialType": p.Cred.CredentialType,
		"holderName":     p.Holder.FullName(),
		"holderEmail":    p.Ref.HolderEmail,
		"holderEID":      p.Ref.HolderEID,
		"holderID":       p.Cred.Holder,
		"issueDate":      issuedISO,
		"issuedAt":       issuedISO,
		"issuedBy":       firstNonEmpty(p.Ref.IssuedBy, config.IssuerActorName),
		"status":         p.Status,
		"expiryDate":     expiryOrNil(p.Cred.ExpiryDate),
		"blockchainTxId": p.Ref.FabricCredID,
	}
}

// validCredentialStatus reports whether s is one of the known status filters.
func validCredentialStatus(s string) bool {
	switch s {
	case "active", "revoked", "suspended", "expired":
		return true
	}
	return false
}
