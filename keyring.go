package creds

import "time"

// GenState is the lifecycle state of a key generation.
type GenState string

const (
	GenActive   GenState = "active"   // may sign and verify
	GenRetiring GenState = "retiring" // transition window: may still sign until SignUntil
	GenRetired  GenState = "retired"  // verify only; previously issued credentials expire naturally
)

// Generation is one committed key generation.
type Generation struct {
	ID        uint64    `json:"id"`
	Key       []byte    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
	SignUntil time.Time `json:"sign_until"` // end of transition window for signing
	State     GenState  `json:"state"`
}

// CanSign reports whether this generation may sign new credentials at t.
func (g *Generation) CanSign(t time.Time) bool {
	switch g.State {
	case GenActive:
		return true
	case GenRetiring:
		return t.Before(g.SignUntil)
	default:
		return false
	}
}

// KeyRing is an immutable snapshot of committed generations. Readers only
// ever observe a fully committed KeyRing; rotation swaps it atomically.
type KeyRing struct {
	Generations map[uint64]*Generation
	Current     uint64
}

// clone returns a deep copy safe to mutate before publishing.
func (r *KeyRing) clone() *KeyRing {
	out := &KeyRing{
		Generations: make(map[uint64]*Generation, len(r.Generations)),
		Current:     r.Current,
	}
	for id, g := range r.Generations {
		ng := *g
		ng.Key = append([]byte(nil), g.Key...)
		out.Generations[id] = &ng
	}
	return out
}

// current returns the signing generation.
func (r *KeyRing) current() *Generation { return r.Generations[r.Current] }

// get returns a generation by id.
func (r *KeyRing) get(id uint64) *Generation { return r.Generations[id] }
