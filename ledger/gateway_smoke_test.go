package ledger

// gateway_smoke_test.go — end-to-end check against a live Fabric network
// through the Gateway, using getContract and the identity's own signer
// (ML-DSA or ECDSA). Skipped unless QCHAIN_GATEWAY_SMOKE=1. Uses the usual
// NETWORK_ROOT / CHANNEL_NAME / CHAINCODE_NAME settings; the org and wallet
// identity default to government / issuer1.

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/teamqchain/qchain-backend/config"
)

func TestGatewaySmoke(t *testing.T) {
	if os.Getenv("QCHAIN_GATEWAY_SMOKE") != "1" {
		t.Skip("QCHAIN_GATEWAY_SMOKE not set")
	}
	org := config.GetEnv("QCHAIN_SMOKE_ORG", "government")
	identityName := config.GetEnv("QCHAIN_SMOKE_IDENTITY", "issuer1")

	contract, gw, conn, err := getContract(org, identityName)
	if err != nil {
		t.Fatalf("getContract: %v", err)
	}
	defer conn.Close()
	defer gw.Close()

	holderID := fmt.Sprintf("H-GW-%d", time.Now().Unix())
	result, err := contract.SubmitTransaction("registerHolder", holderID, "Gateway", "Smoke")
	if err != nil {
		t.Fatalf("submit registerHolder: %s", formatFabricError(err))
	}
	t.Logf("registerHolder: %s", result)

	read, err := contract.EvaluateTransaction("getHolder", holderID)
	if err != nil {
		t.Fatalf("evaluate getHolder: %s", formatFabricError(err))
	}
	var holder struct{ ID, FirstName, LastName string }
	if err := json.Unmarshal(read, &holder); err != nil {
		t.Fatalf("parsing getHolder result %q: %v", read, err)
	}
	if holder.ID != holderID {
		t.Fatalf("getHolder returned %+v, want ID %s", holder, holderID)
	}
	t.Logf("getHolder: %s", read)
}
