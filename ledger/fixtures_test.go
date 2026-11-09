package ledger

// Test fixtures for this package's tests. They are copies of the ones in
// pqc/commitment_test.go: Go test files cannot be imported from another
// package, so each package keeps its own small copy.

import "strings"

var (
	testHashA = strings.Repeat("a", 64)
	testHashB = strings.Repeat("b", 64)
)
