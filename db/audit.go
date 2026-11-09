package db

// audit.go — MySQL access for the `portal_audit_log` table: write an audit
// entry, map action strings to the table's ENUM, and read the log (paginated for
// the audit page, and the most-recent slice for the IT-Admin dashboard widget).

import (
	"fmt"
	"log"
	"time"
)

// AuditLogRow is the projection used by /getAuditLogs (full audit page).
type AuditLogRow struct {
	AuditID         string
	Action          string
	Details         string
	PerformedByName string
	PerformedByRole string
	IPAddress       string
	CreatedAt       time.Time
}

// AdminAuditRow is the slimmer projection used by the dashboard recentAudit widget.
type AdminAuditRow struct {
	Action      string
	Details     string
	Role        string
	PerformedBy string
	Timestamp   time.Time
}

// InsertAuditLog appends a row to portal_audit_log. Non-fatal: errors are logged.
func InsertAuditLog(action, details, performedBy, performedByRole, ipAddress string) {
	if Db == nil {
		return
	}
	logID := generateAuditLogID()
	_, err := Db.Exec(`
		INSERT INTO portal_audit_log
		  (audit_id, action, details, performed_by_name, performed_by_role, ip_address)
		VALUES (?, ?, ?, ?, ?, ?)`,
		logID, auditActionToEnum(action), details, performedBy, performedByRole, ipAddress,
	)
	if err != nil {
		log.Printf("insertAuditLog error: %v", err)
	}
}

// auditActionToEnum maps Phase 2 action strings to portal_audit_log ENUM values.
func auditActionToEnum(action string) string {
	switch action {
	case "issued", "revoked", "suspended", "restored", "verified",
		"staff_added", "staff_removed", "settings_changed",
		"schema_created", "schema_archived",
		"policy_created", "policy_deleted",
		"batch_issued", "exported", "login", "logout",
		"verification_failed":
		return action
	case "policy_changed":
		return "policy_created"
	case "system_config":
		return "settings_changed"
	}
	return "verification_failed"
}

// GetAuditLogs returns audit rows newest-first, paginated.
func GetAuditLogs(page, limit int) ([]AuditLogRow, error) {
	if Db == nil {
		return nil, fmt.Errorf("database not configured")
	}
	offset := (page - 1) * limit
	rows, err := Db.Query(`
		SELECT audit_id, action,
		       COALESCE(details, '') AS details,
		       COALESCE(performed_by_name, '') AS performed_by_name,
		       COALESCE(performed_by_role, '') AS performed_by_role,
		       COALESCE(ip_address, '') AS ip_address,
		       created_at
		  FROM portal_audit_log
		 ORDER BY created_at DESC
		 LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditLogRow{}
	for rows.Next() {
		var r AuditLogRow
		if err := rows.Scan(&r.AuditID, &r.Action, &r.Details,
			&r.PerformedByName, &r.PerformedByRole, &r.IPAddress, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecentAuditLogs returns the latest N audit rows for the dashboard recentAudit widget.
func RecentAuditLogs(limit int) ([]AdminAuditRow, error) {
	if Db == nil {
		return nil, fmt.Errorf("database not configured")
	}
	rows, err := Db.Query(`
		SELECT action,
		       COALESCE(details, '') AS details,
		       COALESCE(performed_by_role, '') AS role,
		       COALESCE(performed_by_name, '') AS performed_by,
		       created_at
		  FROM portal_audit_log
		 ORDER BY created_at DESC
		 LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminAuditRow{}
	for rows.Next() {
		var r AdminAuditRow
		if err := rows.Scan(&r.Action, &r.Details, &r.Role, &r.PerformedBy, &r.Timestamp); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
