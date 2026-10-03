package creds

import (
	"sync"
	"testing"
	"time"
)

func TestRotationTransitionWindow(t *testing.T) {
	clk := NewManualClock(time.Now())
	s := testService(t, clk)
	issuer := Actor{Name: "alice", Roles: []string{"issuer"}}
	rotator := Actor{Name: "carol", Roles: []string{"rotator"}}

	// issue under gen 1
	tok1, c1, err := s.Issue(issuer, "svc-a", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if c1.Generation != 1 {
		t.Fatalf("gen = %d, want 1", c1.Generation)
	}

	// rotate -> gen 2 committed, gen 1 retiring
	newGen, err := s.Rotate(rotator)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newGen != 2 {
		t.Fatalf("newGen = %d, want 2", newGen)
	}

	// old credential still verifies during the window
	if _, err := s.Verify(Actor{}, tok1); err != nil {
		t.Fatalf("old credential rejected inside window: %v", err)
	}

	// new issues use gen 2
	_, c2, err := s.Issue(issuer, "svc-b", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if c2.Generation != 2 {
		t.Fatalf("gen = %d, want 2", c2.Generation)
	}

	// after the transition window closes, gen 1 is verify-only:
	// its previously issued credentials still verify until natural expiry
	clk.Advance(11 * time.Minute) // past 10m window, within 1h TTL
	if _, err := s.Verify(Actor{}, tok1); err != nil {
		t.Fatalf("old credential rejected after window: %v", err)
	}
	ring := s.Generations()
	if ring.Generations[1].State != GenRetiring {
		t.Fatalf("gen1 state = %v, want retiring", ring.Generations[1].State)
	}
	if ring.Generations[1].CanSign(clk.Now()) {
		t.Fatal("gen1 can still sign after window closed")
	}
	if !ring.Generations[2].CanSign(clk.Now()) {
		t.Fatal("gen2 cannot sign after window closed")
	}

	// old credential expires naturally at its own TTL
	clk.Advance(time.Hour)
	if _, err := s.Verify(Actor{}, tok1); err == nil {
		t.Fatal("expired old-generation credential accepted")
	} else if r, _ := ReasonOf(err); r != ReasonExpired {
		t.Fatalf("reason = %v, want expired", r)
	}
}

func TestRotationAtomicVisibility(t *testing.T) {
	clk := NewManualClock(time.Now())
	s := testService(t, clk)
	rotator := Actor{Name: "carol", Roles: []string{"rotator"}}

	const rotations = 20
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// reader: every observed ring must be a complete committed snapshot
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			ring := s.Generations()
			cur := ring.Generations[ring.Current]
			if cur == nil {
				t.Error("ring without current generation observed")
				return
			}
			if cur.State != GenActive {
				t.Error("current generation not active in observed ring")
				return
			}
			// all generations up to Current must be present (no gaps)
			for id := uint64(1); id <= ring.Current; id++ {
				if ring.Generations[id] == nil {
					t.Errorf("generation %d missing from committed ring", id)
					return
				}
			}
		}
	}()

	for i := 0; i < rotations; i++ {
		if _, err := s.Rotate(rotator); err != nil {
			t.Fatalf("Rotate: %v", err)
		}
	}
	close(stop)
	wg.Wait()

	if got := s.Generations().Current; got != rotations+1 {
		t.Fatalf("current gen = %d, want %d", got, rotations+1)
	}
}

func TestConcurrentIssueAndRotate(t *testing.T) {
	clk := NewManualClock(time.Now())
	s := testService(t, clk)
	issuer := Actor{Name: "alice", Roles: []string{"issuer"}}
	rotator := Actor{Name: "carol", Roles: []string{"rotator"}}

	const issuers = 8
	const perIssuer = 50
	tokens := make(chan string, issuers*perIssuer)
	var wg sync.WaitGroup

	for i := 0; i < issuers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perIssuer; j++ {
				tok, _, err := s.Issue(issuer, "svc", nil)
				if err != nil {
					t.Errorf("Issue: %v", err)
					return
				}
				tokens <- tok
			}
		}()
	}
	// rotate concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			if _, err := s.Rotate(rotator); err != nil {
				t.Errorf("Rotate: %v", err)
				return
			}
		}
	}()
	wg.Wait()
	close(tokens)

	// every issued token must verify: rotation never invalidates in-use creds
	n := 0
	for tok := range tokens {
		if _, err := s.Verify(Actor{}, tok); err != nil {
			t.Fatalf("token issued during rotation rejected: %v", err)
		}
		n++
	}
	if n != issuers*perIssuer {
		t.Fatalf("verified %d tokens, want %d", n, issuers*perIssuer)
	}

	// issue seq must be unique (no duplicate credential IDs)
	seen := map[string]bool{}
	s.mu.Lock()
	for id := range s.leases {
		if seen[id] {
			t.Fatalf("duplicate credential id %q", id)
		}
		seen[id] = true
	}
	s.mu.Unlock()
}
