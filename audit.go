package creds

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// AuditOp is the audited operation kind.
type AuditOp string

const (
	OpIssue  AuditOp = "issue"
	OpVerify AuditOp = "verify"
	OpRotate AuditOp = "rotate"
	OpRevoke AuditOp = "revoke"
	OpRenew  AuditOp = "renew"
	OpDenied AuditOp = "denied"
)

// AuditEntry is one tamper-evident audit record (hash-chained).
type AuditEntry struct {
	Seq      uint64    `json:"seq"`
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
	Op       AuditOp   `json:"op"`
	Target   string    `json:"target"`
	Decision string    `json:"decision"` // "allow" / "deny" / failure reason
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

// hashEntry computes the chain hash of an entry.
func hashEntry(e *AuditEntry) string {
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	b, _ := json.Marshal(struct {
		Seq      uint64    `json:"seq"`
		At       time.Time `json:"at"`
		Actor    string    `json:"actor"`
		Op       AuditOp   `json:"op"`
		Target   string    `json:"target"`
		Decision string    `json:"decision"`
	}{e.Seq, e.At, e.Actor, e.Op, e.Target, e.Decision})
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// Auditor appends hash-chained audit entries, mirrored into the journal so
// revocation audits survive restarts.
type Auditor struct {
	entries []AuditEntry
	last    string
}

func NewAuditor() *Auditor { return &Auditor{} }

// Append computes the chain hash and stores the entry.
func (a *Auditor) Append(e AuditEntry) AuditEntry {
	e.Seq = uint64(len(a.entries)) + 1
	e.PrevHash = a.last
	e.Hash = hashEntry(&e)
	a.entries = append(a.entries, e)
	a.last = e.Hash
	return e
}

// restore appends an already-hashed entry during journal replay,
// preserving its original chain hash.
func (a *Auditor) restore(e AuditEntry) {
	a.entries = append(a.entries, e)
	a.last = e.Hash
}

// Entries returns a copy of all entries in order.
func (a *Auditor) Entries() []AuditEntry {
	out := make([]AuditEntry, len(a.entries))
	copy(out, a.entries)
	return out
}

// Verify checks the integrity of the hash chain.
func VerifyAuditChain(entries []AuditEntry) bool {
	prev := ""
	for i, e := range entries {
		if e.Seq != uint64(i+1) {
			return false
		}
		if e.PrevHash != prev {
			return false
		}
		if hashEntry(&e) != e.Hash {
			return false
		}
		prev = e.Hash
	}
	return true
}
