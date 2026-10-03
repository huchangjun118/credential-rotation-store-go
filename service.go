package creds

import (
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Config controls service behaviour.
type Config struct {
	JournalPath      string        // WAL file path; empty = in-memory only
	CredentialTTL    time.Duration // default credential lifetime
	TransitionWindow time.Duration // how long the old generation may still sign after rotation
	RenewalMax       time.Duration // max extension per renew
}

func (c *Config) withDefaults() {
	if c.CredentialTTL <= 0 {
		c.CredentialTTL = time.Hour
	}
	if c.TransitionWindow <= 0 {
		c.TransitionWindow = time.Minute
	}
	if c.RenewalMax <= 0 {
		c.RenewalMax = c.CredentialTTL
	}
}

// lease tracks the mutable state of an issued credential.
type lease struct {
	claims   Claims
	revoked  bool
	notAfter time.Time // effective expiry; extended by renew
}

// Service issues, verifies, rotates and revokes credentials locally.
type Service struct {
	cfg     Config
	clock   Clock
	authz   *Authorizer
	ring    atomic.Pointer[KeyRing] // only fully committed snapshots are published
	journal *Journal
	audit   *Auditor

	mu       sync.Mutex // serializes rotation, lease mutations, journal/audit order
	leases   map[string]*lease
	issueSeq uint64
}

// New creates a Service, replaying the journal to recover committed
// generations, revocations, leases and audit history. A rotate_begin without
// a matching gen_commit is discarded, so an interrupted rotation never
// leaks into the recovered state.
func New(cfg Config, clock Clock, authz *Authorizer) (*Service, error) {
	cfg.withDefaults()
	if clock == nil {
		clock = realClock{}
	}
	if authz == nil {
		authz = NewAuthorizer()
	}
	j, err := OpenJournal(cfg.JournalPath)
	if err != nil {
		return nil, err
	}
	s := &Service{
		cfg:     cfg,
		clock:   clock,
		authz:   authz,
		journal: j,
		audit:   NewAuditor(),
		leases:  make(map[string]*lease),
	}
	var ring *KeyRing
	err = j.Replay(func(r *Record) error {
		switch r.Kind {
		case RecGenCommit:
			ring = r.Ring
		case RecIssue:
			if r.Claims != nil {
				s.leases[r.Claims.ID] = &lease{claims: *r.Claims, notAfter: r.Claims.NotAfter}
				if r.Claims.Seq > s.issueSeq {
					s.issueSeq = r.Claims.Seq
				}
			}
		case RecRenew:
			if l, ok := s.leases[r.CredID]; ok {
				l.notAfter = time.Unix(0, r.NotAfter)
			}
		case RecRevoke:
			l, ok := s.leases[r.CredID]
			if !ok {
				l = &lease{claims: Claims{ID: r.CredID}}
				s.leases[r.CredID] = l
			}
			l.revoked = true
		case RecAudit:
			if r.Audit != nil {
				s.audit.restore(*r.Audit)
			}
		case RecRotateBegin:
			// incomplete rotation record: ignored unless a gen_commit follows
		}
		return nil
	})
	if err != nil {
		j.Close()
		return nil, err
	}
	if ring == nil {
		// bootstrap: first committed generation
		ring, err = s.commitRotationLocked(Actor{Name: "system"})
		if err != nil {
			j.Close()
			return nil, err
		}
	}
	s.ring.Store(ring)
	return s, nil
}

// recordAudit appends to the hash chain and mirrors it into the journal so
// audits (notably revocations) survive restarts. Caller holds s.mu.
func (s *Service) recordAudit(actor Actor, op AuditOp, target, decision string) {
	e := s.audit.Append(AuditEntry{
		At:       s.clock.Now(),
		Actor:    actor.Name,
		Op:       op,
		Target:   target,
		Decision: decision,
	})
	// journal is authoritative; a failure here is logged by keeping the
	// in-memory chain only, but we best-effort persist.
	_ = s.journal.Append(&Record{Kind: RecAudit, Audit: &e})
}

// authorize checks a permission and audits denials. Caller holds s.mu.
func (s *Service) authorize(actor Actor, p Permission, op AuditOp, target string) error {
	if s.authz.Allowed(actor, p) {
		return nil
	}
	s.recordAudit(actor, OpDenied, target, fmt.Sprintf("deny: missing %s for %s", p, op))
	return newErr(ReasonPermissionDenied, fmt.Sprintf("actor %q lacks %s", actor.Name, p))
}

// commitRotationLocked builds and journals a new committed ring.
// Caller holds s.mu (or is in New before concurrency exists).
func (s *Service) commitRotationLocked(actor Actor) (*KeyRing, error) {
	now := s.clock.Now()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	var nextID uint64 = 1
	old := s.ring.Load()
	if old != nil {
		nextID = old.Current + 1
	}
	// begin record: if we crash before commit, recovery discards this
	if err := s.journal.Append(&Record{Kind: RecRotateBegin, GenID: nextID}); err != nil {
		return nil, err
	}
	var next *KeyRing
	if old == nil {
		next = &KeyRing{Generations: map[uint64]*Generation{}}
	} else {
		next = old.clone()
		if cur := next.current(); cur != nil && cur.State == GenActive {
			cur.State = GenRetiring
			cur.SignUntil = now.Add(s.cfg.TransitionWindow)
		}
	}
	next.Generations[nextID] = &Generation{
		ID:        nextID,
		Key:       key,
		CreatedAt: now,
		State:     GenActive,
	}
	next.Current = nextID
	// commit record: the full committed ring, applied atomically on replay
	if err := s.journal.Append(&Record{Kind: RecGenCommit, GenID: nextID, Ring: next}); err != nil {
		return nil, err
	}
	s.recordAudit(actor, OpRotate, fmt.Sprintf("gen-%d", nextID), "allow")
	return next, nil
}

// Issue signs a new credential for subject. Requires PermIssue.
func (s *Service) Issue(actor Actor, subject string, roles []string) (string, *Claims, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.authorize(actor, PermIssue, OpIssue, subject); err != nil {
		return "", nil, err
	}
	ring := s.ring.Load()
	gen := ring.current()
	now := s.clock.Now()
	if gen == nil || !gen.CanSign(now) {
		return "", nil, newErr(ReasonRotationConflict, "no signing-capable generation")
	}
	s.issueSeq++
	claims := &Claims{
		ID:         fmt.Sprintf("cred-%d-%d", gen.ID, s.issueSeq),
		Subject:    subject,
		Roles:      roles,
		Generation: gen.ID,
		NotBefore:  now,
		NotAfter:   now.Add(s.cfg.CredentialTTL),
		Seq:        s.issueSeq,
	}
	tok, err := encodeToken(claims, gen.Key)
	if err != nil {
		return "", nil, err
	}
	// journal before publishing the lease: no lost or duplicate issues
	if err := s.journal.Append(&Record{Kind: RecIssue, Claims: claims}); err != nil {
		return "", nil, err
	}
	s.leases[claims.ID] = &lease{claims: *claims, notAfter: claims.NotAfter}
	s.recordAudit(actor, OpIssue, claims.ID, "allow")
	return tok, claims, nil
}

// Verify checks a token: signature, revocation, then time bounds. Failure
// reasons are distinguishable via ReasonOf. Precedence is deterministic:
// malformed/forged first, then revoked, then not-yet-valid, then expired.
func (s *Service) Verify(actor Actor, token string) (*Claims, error) {
	genID, err := splitTokenGen(token)
	if err != nil {
		return nil, err
	}
	ring := s.ring.Load() // atomic: only fully committed rings are visible
	gen := ring.get(genID)
	if gen == nil {
		return nil, newErr(ReasonUnknownKeyGen, fmt.Sprintf("generation %d not committed", genID))
	}
	claims, err := decodeToken(token, gen.Key)
	if err != nil {
		return nil, err // forged or malformed
	}
	s.mu.Lock()
	l, ok := s.leases[claims.ID]
	s.mu.Unlock()
	if !ok {
		return nil, newErr(ReasonMalformed, "unknown credential id")
	}
	if l.revoked {
		return nil, newErr(ReasonRevoked, claims.ID)
	}
	now := s.clock.Now()
	if now.Before(claims.NotBefore) {
		return nil, newErr(ReasonNotYetValid, claims.ID)
	}
	// effective expiry honors renewals
	if !now.Before(l.notAfter) {
		return nil, newErr(ReasonExpired, claims.ID)
	}
	return claims, nil
}

// Rotate commits a new key generation atomically. Requires PermRotate.
// The old generation keeps verifying (and may sign until its transition
// window closes); credentials it issued expire naturally.
func (s *Service) Rotate(actor Actor) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.authorize(actor, PermRotate, OpRotate, "keyring"); err != nil {
		return 0, err
	}
	next, err := s.commitRotationLocked(actor)
	if err != nil {
		return 0, err
	}
	s.ring.Store(next) // atomic publish: readers never see mixed state
	return next.Current, nil
}

// Revoke immediately invalidates a credential. Requires PermRevoke.
// The revocation is journaled (fsync) and audited before returning, so it
// takes effect at once and survives restarts.
func (s *Service) Revoke(actor Actor, credID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.authorize(actor, PermRevoke, OpRevoke, credID); err != nil {
		return err
	}
	l, ok := s.leases[credID]
	if !ok {
		return newErr(ReasonMalformed, "unknown credential id")
	}
	if l.revoked {
		return nil // idempotent
	}
	if err := s.journal.Append(&Record{Kind: RecRevoke, CredID: credID}); err != nil {
		return err
	}
	l.revoked = true // terminal: concurrent renew serialized behind s.mu
	s.recordAudit(actor, OpRevoke, credID, "allow")
	return nil
}

// Renew extends a credential's lease, bounded by its generation's lifecycle
// and the configured TTL. Requires PermRenew.
func (s *Service) Renew(actor Actor, credID string, extend time.Duration) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.authorize(actor, PermRenew, OpRenew, credID); err != nil {
		return time.Time{}, err
	}
	l, ok := s.leases[credID]
	if !ok {
		return time.Time{}, newErr(ReasonMalformed, "unknown credential id")
	}
	if l.revoked {
		return time.Time{}, newErr(ReasonRevoked, credID)
	}
	now := s.clock.Now()
	if !now.Before(l.notAfter) {
		return time.Time{}, newErr(ReasonExpired, credID)
	}
	if extend <= 0 || extend > s.cfg.RenewalMax {
		return time.Time{}, newErr(ReasonLeaseConflict, "extension out of bounds")
	}
	newNA := l.notAfter.Add(extend)
	// never beyond a fresh TTL from now
	if max := now.Add(s.cfg.CredentialTTL); newNA.After(max) {
		newNA = max
	}
	// never beyond the issuing generation's lifecycle
	ring := s.ring.Load()
	if gen := ring.get(l.claims.Generation); gen != nil && gen.State != GenActive {
		genEnd := gen.SignUntil.Add(s.cfg.CredentialTTL)
		if newNA.After(genEnd) {
			newNA = genEnd
		}
	}
	if !newNA.After(l.notAfter) {
		return time.Time{}, newErr(ReasonLeaseConflict, "renewal cannot extend beyond generation lifecycle")
	}
	if err := s.journal.Append(&Record{Kind: RecRenew, CredID: credID, NotAfter: newNA.UnixNano()}); err != nil {
		return time.Time{}, err
	}
	l.notAfter = newNA
	s.recordAudit(actor, OpRenew, credID, "allow")
	return newNA, nil
}

// Generations returns a snapshot of the committed key ring (deep copy).
func (s *Service) Generations() *KeyRing {
	return s.ring.Load().clone()
}

// AuditLog returns the full audit chain.
func (s *Service) AuditLog() []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.audit.Entries()
}

// Close flushes and closes the journal.
func (s *Service) Close() error {
	return s.journal.Close()
}
