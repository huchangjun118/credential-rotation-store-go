package creds

import (
	"sync"
	"testing"
	"time"
)

func TestRenewExtendsLease(t *testing.T) {
	clk := NewManualClock(time.Now())
	s := testService(t, clk)
	issuer := Actor{Name: "alice", Roles: []string{"issuer"}}

	tok, c, err := s.Issue(issuer, "svc", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// half the TTL passes, then renew by 30m: effective expiry 1h30m from start
	clk.Advance(30 * time.Minute)
	newNA, err := s.Renew(issuer, c.ID, 30*time.Minute)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if !newNA.Equal(c.NotAfter.Add(30 * time.Minute)) {
		t.Fatalf("newNA = %v, want %v", newNA, c.NotAfter.Add(30*time.Minute))
	}
	// past original expiry, still valid thanks to renewal
	clk.Advance(45 * time.Minute) // now = 1h15m
	if _, err := s.Verify(Actor{}, tok); err != nil {
		t.Fatalf("renewed credential rejected: %v", err)
	}
	// past renewed expiry, rejected
	clk.Advance(20 * time.Minute)
	if _, err := s.Verify(Actor{}, tok); err == nil {
		t.Fatal("credential valid past renewed expiry")
	} else if r, _ := ReasonOf(err); r != ReasonExpired {
		t.Fatalf("reason = %v, want expired", r)
	}
}

func TestRenewBoundedByGenerationLifecycle(t *testing.T) {
	clk := NewManualClock(time.Now())
	s := testService(t, clk) // TTL=1h, window=10m, RenewalMax=30m
	issuer := Actor{Name: "alice", Roles: []string{"issuer"}}
	rotator := Actor{Name: "carol", Roles: []string{"rotator"}}

	_, c, err := s.Issue(issuer, "svc", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Rotate(rotator); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// gen 1 lifecycle ends at SignUntil + TTL = rotate+10m+1h.
	// Renew repeatedly: expiry must never pass that bound.
	genEnd := clk.Now().Add(10*time.Minute + time.Hour)
	prev := c.NotAfter
	for i := 0; i < 10; i++ {
		na, err := s.Renew(issuer, c.ID, 30*time.Minute)
		if err != nil {
			break // lease_conflict once the bound is reached
		}
		if na.After(genEnd) {
			t.Fatalf("renewal escaped generation lifecycle: %v > %v", na, genEnd)
		}
		if !na.After(prev) {
			t.Fatalf("renewal did not move forward: %v <= %v", na, prev)
		}
		prev = na
	}
	if prev.After(genEnd) {
		t.Fatalf("final expiry %v beyond generation end %v", prev, genEnd)
	}
}

func TestRenewRevokeRace(t *testing.T) {
	clk := NewManualClock(time.Now())
	s := testService(t, clk)
	issuer := Actor{Name: "alice", Roles: []string{"issuer"}}
	revoker := Actor{Name: "bob", Roles: []string{"revoker"}}

	for trial := 0; trial < 50; trial++ {
		tok, c, err := s.Issue(issuer, "svc", nil)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = s.Revoke(revoker, c.ID)
		}()
		go func() {
			defer wg.Done()
			_, _ = s.Renew(issuer, c.ID, time.Minute)
		}()
		wg.Wait()

		s.mu.Lock()
		l := s.leases[c.ID]
		revoked := l.revoked
		s.mu.Unlock()

		_, verr := s.Verify(Actor{}, tok)
		if revoked {
			// revoke is terminal: credential must be invalid, no valid lease remains
			if verr == nil {
				t.Fatal("revoked credential still verifies after race")
			}
			if r, _ := ReasonOf(verr); r != ReasonRevoked {
				t.Fatalf("reason = %v, want revoked", r)
			}
			// a later renew must fail: no state regression
			if _, err := s.Renew(issuer, c.ID, time.Minute); err == nil {
				t.Fatal("renew after revoke succeeded")
			} else if r, _ := ReasonOf(err); r != ReasonRevoked {
				t.Fatalf("renew-after-revoke reason = %v, want revoked", r)
			}
		} else if verr != nil {
			t.Fatalf("unrevoked credential rejected: %v", verr)
		}
	}
}

func TestRevokeImmediate(t *testing.T) {
	clk := NewManualClock(time.Now())
	s := testService(t, clk)
	issuer := Actor{Name: "alice", Roles: []string{"issuer"}}
	revoker := Actor{Name: "bob", Roles: []string{"revoker"}}

	tok, c, err := s.Issue(issuer, "svc", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Verify(Actor{}, tok); err != nil {
		t.Fatalf("pre-revoke verify: %v", err)
	}
	if err := s.Revoke(revoker, c.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// immediate: same instant, no time advance
	if _, err := s.Verify(Actor{}, tok); err == nil {
		t.Fatal("revoked credential still valid")
	} else if r, _ := ReasonOf(err); r != ReasonRevoked {
		t.Fatalf("reason = %v, want revoked", r)
	}
	// idempotent
	if err := s.Revoke(revoker, c.ID); err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
}
