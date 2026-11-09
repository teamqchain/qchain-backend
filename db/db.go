package db

// Db.go — the database connection itself and the display-ID sequence counters.
//
// This file owns the package-wide handle DB and InitDB (called once from
// main). All the actual queries live in this folder's domain files holders.go,
// credentials.go, verification.go, dashboard.go, audit.go, subscriptions.go,
// staff.go and mobile.go — they all use DB.
//
// Design note: every query function guards `if db == nil` and degrades to a
// warning rather than crashing, so the server still boots when MYSQL_DSN is unset.

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	// The blank import (`_`) registers the MySQL driver with database/sql for its
	// side effects; we never call it by name, so the underscore avoids an
	// "imported and not used" error.
	_ "github.com/go-sql-driver/mysql"
)

// Db is the shared connection pool used by every db_*.go query function.
var Db *sql.DB

// displayCredSeq is an atomic counter for sequential display credential IDs (CRED-0001, CRED-0002...).
// Seeded from the MAX value in MySQL on startup so IDs never collide across restarts.
var displayCredSeq uint64

// displayHolderSeq is an atomic counter for sequential holder IDs (H-0001, H-0002...).
var displayHolderSeq uint64

// InitDB connects to MySQL using MYSQL_DSN env var.
// Non-fatal: if MYSQL_DSN is absent or ping fails, db remains nil and all DB
// operations log warnings but don't crash the server.
func InitDB() {
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		log.Println("MYSQL_DSN not set — database features disabled (holder/credential lookups will fail)")
		return
	}
	// Ensure the connection parses DATETIME/TIMESTAMP into time.Time AND treats
	// every timestamp as UAE local time (Asia/Dubai, always +04:00), so all times
	// we read and write are UAE-consistent end to end:
	//   • parseTime — scan DATETIME/TIMESTAMP columns into time.Time
	//   • loc       — tag those time.Time values as Asia/Dubai
	//   • time_zone — pin the MySQL session to +04:00 so TIMESTAMP columns convert
	//                 consistently regardless of the MySQL server's own timezone
	// addDSNParam appends a key only if the DSN doesn't already set it, so it is
	// safe whatever MYSQL_DSN already contains.
	addDSNParam := func(key, value string) {
		if strings.Contains(dsn, key+"=") {
			return
		}
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + key + "=" + value
	}
	addDSNParam("parseTime", "true")
	addDSNParam("loc", "Asia%2FDubai")
	addDSNParam("time_zone", "%27%2B04%3A00%27") // time_zone='+04:00'

	var err error
	Db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("DB open failed: %v — database features disabled", err)
		Db = nil
		return
	}

	Db.SetMaxOpenConns(10)
	Db.SetMaxIdleConns(5)
	Db.SetConnMaxLifetime(5 * time.Minute)

	if err := Db.Ping(); err != nil {
		log.Printf("DB ping failed: %v — database features disabled", err)
		Db = nil
		return
	}

	// Seed the credential display ID counter from the current MAX so we never re-use a display ID.
	var maxCredSeq sql.NullInt64
	_ = Db.QueryRow(
		`SELECT COALESCE(MAX(CAST(SUBSTRING(credential_id, 6) AS UNSIGNED)), 0) FROM credentials`,
	).Scan(&maxCredSeq)
	if maxCredSeq.Valid && maxCredSeq.Int64 > 0 {
		atomic.StoreUint64(&displayCredSeq, uint64(maxCredSeq.Int64))
	}

	// Seed the holder display ID counter similarly.
	var maxHolderSeq sql.NullInt64
	_ = Db.QueryRow(
		`SELECT COALESCE(MAX(CAST(SUBSTRING(holder_id, 3) AS UNSIGNED)), 0) FROM holders`,
	).Scan(&maxHolderSeq)
	if maxHolderSeq.Valid && maxHolderSeq.Int64 > 0 {
		atomic.StoreUint64(&displayHolderSeq, uint64(maxHolderSeq.Int64))
	}

	log.Println("MySQL connected successfully")
}

// NextDisplayCredID returns the next sequential display credential ID (CRED-0001, CRED-0002...).
// atomic.AddUint64 increments the shared counter safely even under concurrent requests.
func NextDisplayCredID() string {
	n := atomic.AddUint64(&displayCredSeq, 1)
	return fmt.Sprintf("CRED-%04d", n)
}

// NextHolderID returns the next sequential holder ID (H-0001, H-0002...) and persists the
// counter via atomic increment.
func NextHolderID() (string, error) {
	n := atomic.AddUint64(&displayHolderSeq, 1)
	return fmt.Sprintf("H-%04d", n), nil
}
