package db

// staff.go — MySQL access for the `staff` and `org_directory` tables: list,
// invite, look up, re-role and soft-delete staff, read the HR directory, and the
// staff count/breakdown queries the IT-Admin dashboard shows.

import (
	"database/sql"
	"fmt"
	"time"
)

// StaffRow is the projection used by /getStaff and staff lookups.
type StaffRow struct {
	ID        string
	Name      string
	Email     string
	Portal    string
	Role      string
	Status    string
	AddedDate time.Time
}

// RoleCount is one {role, count} pair in the dashboard staff-role breakdown.
type RoleCount struct {
	Label string
	Count int
}

// OrgDirectoryRecord holds a single employee entry from the HR directory.
type OrgDirectoryRecord struct {
	Name  string
	Email string
}

// GetStaff lists all non-deleted staff members, newest first.
func GetStaff() ([]StaffRow, error) {
	if Db == nil {
		return nil, fmt.Errorf("database not configured")
	}
	rows, err := Db.Query(`
		SELECT id, name, email, portal, role, status, added_date
		  FROM staff
		 WHERE status != 'deleted'
		 ORDER BY added_date DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StaffRow{}
	for rows.Next() {
		var r StaffRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Email, &r.Portal, &r.Role, &r.Status, &r.AddedDate); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// StaffEmailExists reports whether any staff row already uses this email.
func StaffEmailExists(email string) (bool, error) {
	if Db == nil {
		return false, fmt.Errorf("database not configured")
	}
	var count int
	err := Db.QueryRow(`SELECT COUNT(*) FROM staff WHERE email = ?`, email).Scan(&count)
	return count > 0, err
}

// InsertStaff creates an invited staff row (name filled in later on acceptance).
func InsertStaff(id, email, portal, role string) error {
	if Db == nil {
		return fmt.Errorf("database not configured")
	}
	_, err := Db.Exec(`
		INSERT INTO staff (id, name, email, portal, role, status, added_date)
		VALUES (?, '', ?, ?, ?, 'invited', CURDATE())`,
		id, email, portal, role,
	)
	return err
}

// GetStaffByID fetches one non-deleted staff member; returns sql.ErrNoRows if absent.
func GetStaffByID(id string) (StaffRow, error) {
	var r StaffRow
	if Db == nil {
		return r, fmt.Errorf("database not configured")
	}
	err := Db.QueryRow(`
		SELECT id, name, email, portal, role, status, added_date
		  FROM staff WHERE id = ? AND status != 'deleted' LIMIT 1`, id).Scan(
		&r.ID, &r.Name, &r.Email, &r.Portal, &r.Role, &r.Status, &r.AddedDate,
	)
	if err == sql.ErrNoRows {
		return r, sql.ErrNoRows
	}
	return r, err
}

// UpdateStaffRole changes a staff member's portal and role.
func UpdateStaffRole(id, portal, role string) error {
	if Db == nil {
		return fmt.Errorf("database not configured")
	}
	_, err := Db.Exec(`UPDATE staff SET portal = ?, role = ? WHERE id = ?`, portal, role, id)
	return err
}

// SoftDeleteStaff marks a staff member deleted (row is kept for audit).
func SoftDeleteStaff(id string) error {
	if Db == nil {
		return fmt.Errorf("database not configured")
	}
	_, err := Db.Exec(`UPDATE staff SET status = 'deleted' WHERE id = ?`, id)
	return err
}

// GetOrgDirectory returns all active employees from the org_directory table.
// It backs the QPortal Invite Staff dialog, which only lets staff invite
// emails that exist in this directory.
func GetOrgDirectory() ([]OrgDirectoryRecord, error) {
	if Db == nil {
		return nil, fmt.Errorf("database not configured")
	}
	rows, err := Db.Query(`
		SELECT name, email
		  FROM org_directory
		 WHERE is_active = TRUE
		 ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []OrgDirectoryRecord{}
	for rows.Next() {
		var r OrgDirectoryRecord
		if err := rows.Scan(&r.Name, &r.Email); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ─── DASHBOARD STAFF AGGREGATIONS ────────────────────────────────────────────

// StaffCounts returns issuer + verifier staff counts from the unified staff table.
func StaffCounts() (issuers, verifiers int, err error) {
	if Db == nil {
		return 0, 0, fmt.Errorf("database not configured")
	}
	_ = Db.QueryRow(`SELECT COUNT(*) FROM staff WHERE portal = 'issuer'   AND status != 'deleted'`).Scan(&issuers)
	_ = Db.QueryRow(`SELECT COUNT(*) FROM staff WHERE portal = 'verifier' AND status != 'deleted'`).Scan(&verifiers)
	return issuers, verifiers, nil
}

// StaffTotals returns total / active / invited staff counts.
func StaffTotals() (total, active, invited int, err error) {
	if Db == nil {
		return 0, 0, 0, fmt.Errorf("database not configured")
	}
	_ = Db.QueryRow(`SELECT COUNT(*) FROM staff WHERE status != 'deleted'`).Scan(&total)
	_ = Db.QueryRow(`SELECT COUNT(*) FROM staff WHERE status = 'active'`).Scan(&active)
	_ = Db.QueryRow(`SELECT COUNT(*) FROM staff WHERE status = 'invited'`).Scan(&invited)
	return total, active, invited, nil
}

// StaffRoleBreakdown returns non-admin role counts for one portal, most common first.
func StaffRoleBreakdown(portal string) ([]RoleCount, error) {
	if Db == nil {
		return nil, fmt.Errorf("database not configured")
	}
	rows, err := Db.Query(`
		SELECT role AS label, COUNT(*) AS count
		  FROM staff
		 WHERE portal = ? AND status != 'deleted' AND role != 'admin'
		 GROUP BY role ORDER BY count DESC`, portal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RoleCount{}
	for rows.Next() {
		var r RoleCount
		if err := rows.Scan(&r.Label, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
