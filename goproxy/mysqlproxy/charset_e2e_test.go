package mysqlproxy_test

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// TestResultsCharsetNULLRewrittenOnBackendHopOnly is the #81 wire flip against a real MySQL backend: a
// session that sets character_set_results = NULL (Connector/J's default, so DBeaver's) is no longer failed
// closed. The SET succeeds because the backend is pinned to utf8mb4; a subsequent masked read still returns
// the mask (proving results stay maskable under the pin); and the control plane sees the ORIGINAL statement,
// proving the pin is a backend-hop rewrite, not an authz/audit substitution.
func TestResultsCharsetNULLRewrittenOnBackendHopOnly(t *testing.T) {
	const setNULL = "SET character_set_results = NULL"
	const maskedRead = "SELECT id, name, ssn FROM people ORDER BY id"

	h := startBroker(t)
	// ALLOW the SET; MASK the ssn column on the read, so the read exercises the masker under the pinned
	// charset — a broken pin (NULL results charset) would either fail the session closed or corrupt the mask.
	h.fake.decideFn = func(req *pb.DecisionRequest) (*pb.WireDecision, error) {
		if req.GetSql() == maskedRead {
			return wireVerdict(&pb.Verdict{
				Decision: pb.EnfAction_MASK,
				Masks:    []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(2)}},
			}), nil
		}
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW}), nil
	}
	client := openRawClient(t, h.addr, validToken)

	// The SET itself now succeeds (OK, not the fail-closed charset ERR): the backend receives utf8mb4.
	response := client.firstQueryPacket(t, setNULL)
	if len(response) == 0 || response[0] != 0x00 {
		t.Fatalf("SET character_set_results = NULL response = %x, want OK (pinned to utf8mb4)", response)
	}
	// The session stays open and maskable: ssn is masked to the fixed token, unmasked columns and the NULL
	// row are untouched.
	rows := client.textRows(t, maskedRead, 3)
	if len(rows) != 2 {
		t.Fatalf("masked read rows = %d, want 2", len(rows))
	}
	if rows[0][2] == nil || *rows[0][2] != "####" {
		t.Fatalf("row 0 ssn = %v, want masked \"####\"", rows[0][2])
	}
	if rows[1][2] != nil {
		t.Fatalf("row 1 ssn = %v, want NULL preserved", rows[1][2])
	}

	// Authorization and audit saw the statement the client actually sent, not the utf8mb4 rewrite.
	var sawOriginal bool
	for _, req := range h.fake.requests() {
		if req.GetSql() == "SET character_set_results = utf8mb4" {
			t.Fatalf("control plane saw the backend-hop rewrite %q; authz/audit must see the original", req.GetSql())
		}
		if req.GetSql() == setNULL {
			sawOriginal = true
		}
	}
	if !sawOriginal {
		t.Fatalf("no Decide request carried the original %q", setNULL)
	}
}

// TestResultsCharsetNonNullStillFailsClosed proves the rewrite is surgical: only NULL is pinned. An explicit
// non-UTF-8 results charset still trips the session charset invariant and fails the session closed, so a miss
// in the narrow NULL rewrite can never open a masking hole.
func TestResultsCharsetNonNullStillFailsClosed(t *testing.T) {
	h := startBroker(t)
	h.fake.decideFn = allowAllDecide
	client := openRawClient(t, h.addr, validToken)

	response := client.firstQueryPacket(t, "SET character_set_results = latin1")
	if len(response) == 0 || response[0] != 0xff {
		t.Fatalf("SET character_set_results = latin1 response = %x, want fail-closed ERR", response)
	}
	if got := mysqlwire.ErrString(response); !strings.Contains(got, "utf8mb4/utf8") {
		t.Fatalf("SET character_set_results = latin1 error = %q, want an unsafe-charset fail-closed", got)
	}
}
