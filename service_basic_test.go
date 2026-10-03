package creds

import (
	"strings"
	"testing"
	"time"
)

func testAuthz() *Authorizer {
	z := NewAuthorizer()
	z.Grant("issuer", PermIssue)
	z.Grant("issuer", PermRenew)
	z.Grant("revoker", PermRevoke)
	z.Grant("rotator", PermRotate)
	return z
}

func testService(t *testing.T, clk *ManualClock) *Service {
	t.Helper()
	s, err := New(Config{
		CredentialTTL:    time.Hour,
		TransitionWindow: 10 * time.Minute,
		RenewalMax:       30 * time.Minute,
	}, clk, testAuthz())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestIssueVerifyHappyPath(t *testing.T) {
	clk := NewManualClock(time.Now())
	s := testService(t, clk)
	issuer := Actor{Name: "alice", Roles: []string{"issuer"}}

	tok, claims, err := s.Issue(issuer, "svc-a", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := s.Verify(Actor{Name: "anyone"}, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.ID != claims.ID || got.Subject != "svc-a" {
		t.Fatalf("claims mismatch: %+v", got)
	}
}

func TestVerifyFailureReasonsDistinct(t *testing.T) {
	clk := NewManualClock(time.Now())
	s := testService(t, clk)
	issuer := Actor{Name: "alice", Roles: []string{"issuer"}}
	revoker := Actor{Name: "bob", Roles: []string{"revoker"}}

	tok, claims, err := s.Issue(issuer, "svc-a", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// forged: tamper with signature
	forged := tok[:len(tok)-2] + "xx"
	if _, err := s.Verify(Actor{}, forged); err == nil {
		t.Fatal("forged token accepted")
	} else if r, _ := ReasonOf(err); r != ReasonForged {
		t.Fatalf("forged reason = %v, want %v", r, ReasonForged)
	}

	// expired: advance past TTL
	clk.Advance(2 * time.Hour)
	if _, err := s.Verify(Actor{}, tok); err == nil {
		t.Fatal("expired token accepted")
	} else if r, _ := ReasonOf(err); r != ReasonExpired {
		t.Fatalf("expired reason = %v, want %v", r, ReasonExpired)
	}

	// revoked: fresh token, revoke, then verify
	clk2 := NewManualClock(time.Now())
	s2 := testService(t, clk2)
	tok2, c2, err := s2.Issue(issuer, "svc-b", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s2.Revoke(revoker, c2.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := s2.Verify(Actor{}, tok2); err == nil {
		t.Fatal("revoked token accepted")
	} else if r, _ := ReasonOf(err); r != ReasonRevoked {
		t.Fatalf("revoked reason = %v, want %v", r, ReasonRevoked)
	}
	_ = claims
}

func TestMalformedAndUnknownGeneration(t *testing.T) {
	clk := NewManualClock(time.Now())
	s := testService(t, clk)

	if _, err := s.Verify(Actor{}, "not-a-token"); err == nil {
		t.Fatal("malformed token accepted")
	} else if r, _ := ReasonOf(err); r != ReasonMalformed {
		t.Fatalf("reason = %v, want malformed", r)
	}

	// token signed by a different service (unknown generation id 99)
	other := &Claims{ID: "x", Generation: 99, NotBefore: clk.Now(), NotAfter: clk.Now().Add(time.Hour)}
	tok, err := encodeToken(other, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(Actor{}, tok); err == nil {
		t.Fatal("unknown-generation token accepted")
	} else if r, _ := ReasonOf(err); r != ReasonUnknownKeyGen {
		t.Fatalf("reason = %v, want unknown_key_generation", r)
	}
}

func TestPermissionDeniedIsAudited(t *testing.T) {
	clk := NewManualClock(time.Now())
	s := testService(t, clk)
	nobody := Actor{Name: "mallory"}

	if _, _, err := s.Issue(nobody, "svc", nil); err == nil {
		t.Fatal("issue without permission accepted")
	} else if r, _ := ReasonOf(err); r != ReasonPermissionDenied {
		t.Fatalf("reason = %v, want permission_denied", r)
	}
	if _, err := s.Rotate(nobody); err == nil {
		t.Fatal("rotate without permission accepted")
	}
	if err := s.Revoke(nobody, "cred-1-1"); err == nil {
		t.Fatal("revoke without permission accepted")
	}

	entries := s.AuditLog()
	var denies int
	for _, e := range entries {
		if e.Op == OpDenied && e.Actor == "mallory" {
			denies++
			if !strings.Contains(e.Decision, "deny") {
				t.Fatalf("denial entry missing decision: %+v", e)
			}
		}
	}
	if denies != 3 {
		t.Fatalf("expected 3 denial audits, got %d", denies)
	}
	if !VerifyAuditChain(entries) {
		t.Fatal("audit chain integrity check failed")
	}
}
