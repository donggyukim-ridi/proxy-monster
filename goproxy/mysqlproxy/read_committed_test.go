package mysqlproxy

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// scriptedSetTarget fakes the target-DB end of a freshly-authenticated connection: it reads COM_QUERY
// packets, records each statement, and answers them from replies in order (a nil reply answers OK).
func scriptedSetTarget(t *testing.T, replies ...[]byte) (net.Conn, <-chan string) {
	t.Helper()
	proxySide, targetSide := net.Pipe()
	t.Cleanup(func() { _ = proxySide.Close(); _ = targetSide.Close() })
	_ = proxySide.SetDeadline(time.Now().Add(5 * time.Second))
	_ = targetSide.SetDeadline(time.Now().Add(5 * time.Second))

	statements := make(chan string, len(replies)+2)
	go func() {
		defer close(statements)
		for i := 0; ; i++ {
			seq, payload, err := mysqlwire.ReadPacket(targetSide)
			if err != nil {
				return
			}
			if len(payload) == 0 || payload[0] != 0x03 {
				return
			}
			statements <- string(payload[1:])
			reply := mysqlwire.OKPacket()
			if i < len(replies) && replies[i] != nil {
				reply = replies[i]
			}
			if err := mysqlwire.WritePacket(targetSide, seq+1, reply); err != nil {
				return
			}
		}
	}()
	return proxySide, statements
}

func drain(statements <-chan string) []string {
	var got []string
	for s := range statements {
		got = append(got, s)
	}
	return got
}

func TestApplyReadCommittedIsOptOut(t *testing.T) {
	conn, statements := scriptedSetTarget(t)

	if err := applyReadCommitted(conn, spi.TargetDb{}); err != nil {
		t.Fatalf("applyReadCommitted: %v", err)
	}
	_ = conn.Close()

	if got := drain(statements); len(got) != 0 {
		t.Errorf("a target with ReadCommitted unset must issue no SET, got %q", got)
	}
}

// The Aurora setting must precede the isolation level: an Aurora reader ignores the isolation level unless
// aurora_read_replica_read_committed is already ON in the same session, and does so without an error.
func TestApplyReadCommittedSetsAuroraFlagFirst(t *testing.T) {
	conn, statements := scriptedSetTarget(t)

	if err := applyReadCommitted(conn, spi.TargetDb{ReadCommitted: true}); err != nil {
		t.Fatalf("applyReadCommitted: %v", err)
	}
	_ = conn.Close()

	got := drain(statements)
	if len(got) != 2 {
		t.Fatalf("want 2 statements, got %d: %q", len(got), got)
	}
	if !strings.Contains(got[0], "aurora_read_replica_read_committed = ON") {
		t.Errorf("first statement = %q, want the Aurora reader setting", got[0])
	}
	if !strings.Contains(got[1], "transaction_isolation = 'READ-COMMITTED'") {
		t.Errorf("second statement = %q, want the isolation level", got[1])
	}
}

// A server without the Aurora setting reports ER_UNKNOWN_SYSTEM_VARIABLE. That is the expected answer off
// Aurora, so the connection survives and the isolation level is still applied.
func TestApplyReadCommittedToleratesMissingAuroraFlag(t *testing.T) {
	conn, statements := scriptedSetTarget(t, mysqlwire.ErrPacket(erUnknownSystemVariable, "Unknown system variable 'aurora_read_replica_read_committed'"))

	if err := applyReadCommitted(conn, spi.TargetDb{ReadCommitted: true}); err != nil {
		t.Fatalf("a missing Aurora setting must not fail the connection: %v", err)
	}
	_ = conn.Close()

	got := drain(statements)
	if len(got) != 2 {
		t.Fatalf("want 2 statements, got %d: %q", len(got), got)
	}
	if !strings.Contains(got[1], "transaction_isolation = 'READ-COMMITTED'") {
		t.Errorf("second statement = %q, want the isolation level applied anyway", got[1])
	}
}

// Tolerance is scoped to the one code that means "this engine does not have the variable". Any other
// failure on the Aurora setting still fails the connection rather than leaving the session under an
// isolation level the caller did not ask for.
func TestApplyReadCommittedFailsOnOtherAuroraFlagError(t *testing.T) {
	conn, _ := scriptedSetTarget(t, mysqlwire.ErrPacket(1227, "Access denied; you need SUPER privileges"))

	err := applyReadCommitted(conn, spi.TargetDb{ReadCommitted: true})
	if err == nil {
		t.Fatal("want an error when the Aurora setting fails for a reason other than being unknown")
	}
	if !strings.Contains(err.Error(), "reader read-committed") {
		t.Errorf("error = %v, want it to name the failing step", err)
	}
}

// A server that rejects the isolation level itself is a hard failure: the caller asked for READ COMMITTED
// and did not get it.
func TestApplyReadCommittedFailsWhenIsolationRejected(t *testing.T) {
	conn, _ := scriptedSetTarget(t, nil, mysqlwire.ErrPacket(erUnknownSystemVariable, "Unknown system variable 'transaction_isolation'"))

	err := applyReadCommitted(conn, spi.TargetDb{ReadCommitted: true})
	if err == nil {
		t.Fatal("want an error when the isolation level cannot be set")
	}
	if !strings.Contains(err.Error(), "transaction isolation") {
		t.Errorf("error = %v, want it to name the failing step", err)
	}
}
