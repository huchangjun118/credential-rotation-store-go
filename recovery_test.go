package creds

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func reopen(t *testing.T, path string, clk *ManualClock) *Service {
	t.Helper()
	s, err := New(Config{
		JournalPath:      path,
		CredentialTTL:    time.Hour,
		TransitionWindow: 10 * time.Minute,
		RenewalMax:       30 * time.Minute,
	}, clk, testAuthz())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	return s
}

func TestRestartRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.log")
	clk := NewManualClock(time.Now())
	issuer := Actor{Name: "alice", Roles: []string{"issuer"}}
	revoker := Actor{Name: "bob", Roles: []string{"revoker"}}
	rotator := Actor{Name: "carol", Roles: []string{"rotator"}}

	s1 := reopen(t, path, clk)
	tokKeep, cKeep, err := s1.Issue(issuer, "svc-keep", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tokGone, cGone, err := s1.Issue(issuer, "svc-gone", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s1.Rotate(rotator); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := s1.Revoke(revoker, cGone.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	auditsBefore := s1.AuditLog()
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// restart: replay the journal
	s2 := reopen(t, path, clk)
	defer s2.Close()

	// committed generation survived
	if got := s2.Generations().Current; got != 2 {
		t.Fatalf("current gen after restart = %d, want 2", got)
	}
	// unrevoked credential still verifies
	if _, err := s2.Verify(Actor{}, tokKeep); err != nil {
		t.Fatalf("valid credential rejected after restart: %v", err)
	}
	// revocation survived the restart
	if _, err := s2.Verify(Actor{}, tokGone); err == nil {
		t.Fatal("revoked credential valid after restart")
	} else if r, _ := ReasonOf(err); r != ReasonRevoked {
		t.Fatalf("reason = %v, want revoked", r)
	}
	// revoke audit survived and the chain still verifies
	auditsAfter := s2.AuditLog()
	if len(auditsAfter) != len(auditsBefore) {
		t.Fatalf("audit entries: before=%d after=%d", len(auditsBefore), len(auditsAfter))
	}
	if !VerifyAuditChain(auditsAfter) {
		t.Fatal("audit chain broken after restart")
	}
	var sawRevoke bool
	for _, e := range auditsAfter {
		if e.Op == OpRevoke && e.Target == cGone.ID && e.Decision == "allow" {
			sawRevoke = true
		}
	}
	if !sawRevoke {
		t.Fatal("revoke audit missing after restart")
	}
	// no duplicate credential IDs after restart: seq continues
	_, cNew, err := s2.Issue(issuer, "svc-new", nil)
	if err != nil {
		t.Fatalf("Issue after restart: %v", err)
	}
	if cNew.ID == cKeep.ID || cNew.ID == cGone.ID {
		t.Fatalf("duplicate credential id after restart: %s", cNew.ID)
	}
	if cNew.Generation != 2 {
		t.Fatalf("new issue gen = %d, want 2", cNew.Generation)
	}
}

func TestIncompleteRotationDiscarded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.log")
	clk := NewManualClock(time.Now())
	rotator := Actor{Name: "carol", Roles: []string{"rotator"}}

	s1 := reopen(t, path, clk)
	if _, err := s1.Rotate(rotator); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	committed := s1.Generations().Current
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// simulate a crash mid-rotation: a rotate_begin with no gen_commit
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	if err := j.Append(&Record{Kind: RecRotateBegin, GenID: committed + 1}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	j.Close()

	// recovery must discard the incomplete rotation
	s2 := reopen(t, path, clk)
	defer s2.Close()
	if got := s2.Generations().Current; got != committed {
		t.Fatalf("current gen = %d, want %d (incomplete rotation leaked)", got, committed)
	}
	if _, ok := s2.Generations().Generations[committed+1]; ok {
		t.Fatal("uncommitted generation visible after recovery")
	}
}

func TestTornJournalTailIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.log")
	clk := NewManualClock(time.Now())
	issuer := Actor{Name: "alice", Roles: []string{"issuer"}}

	s1 := reopen(t, path, clk)
	tok, _, err := s1.Issue(issuer, "svc", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	s1.Close()

	// append garbage simulating a torn write at crash time
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"kind":"gen_commit","ring":{"Gen` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	s2 := reopen(t, path, clk)
	defer s2.Close()
	if _, err := s2.Verify(Actor{}, tok); err != nil {
		t.Fatalf("valid credential rejected after torn-tail recovery: %v", err)
	}
}
