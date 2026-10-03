package creds

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
)

// RecordKind identifies the type of a journal record.
type RecordKind string

const (
	RecRotateBegin RecordKind = "rotate_begin"
	RecGenCommit   RecordKind = "gen_commit"
	RecIssue       RecordKind = "issue"
	RecRevoke      RecordKind = "revoke"
	RecRenew       RecordKind = "renew"
	RecAudit       RecordKind = "audit"
)

// Record is one journal entry.
type Record struct {
	Kind RecordKind `json:"kind"`
	// rotate_begin: candidate generation id; gen_commit: full committed ring
	GenID uint64   `json:"gen_id,omitempty"`
	Ring  *KeyRing `json:"ring,omitempty"`
	// issue: full claims
	Claims *Claims `json:"claims,omitempty"`
	// revocation / lease fields
	CredID   string `json:"cred_id,omitempty"`
	NotAfter int64  `json:"not_after,omitempty"`
	// audit payload
	Audit *AuditEntry `json:"audit,omitempty"`
}

// Journal is an append-only WAL. Committed generations and revocations are
// replayed on recovery; a rotate_begin without a matching gen_commit is
// discarded, so incomplete rotations never leak into the recovered state.
//
// A nil *os.File (in-memory mode) keeps records only in memory.
type Journal struct {
	mu   sync.Mutex
	path string
	f    *os.File
	mem  []*Record // in-memory records when path == ""
}

// OpenJournal opens (creating if needed) the WAL at path. An empty path
// selects in-memory mode.
func OpenJournal(path string) (*Journal, error) {
	j := &Journal{path: path}
	if path == "" {
		return j, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	j.f = f
	return j, nil
}

// Append durably writes one record (fsync) before returning.
func (j *Journal) Append(r *Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		j.mem = append(j.mem, r)
		return nil
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := j.f.Write(append(data, '\n')); err != nil {
		return err
	}
	return j.f.Sync()
}

// Replay invokes fn for each record in order. A torn trailing line (from a
// crash mid-write) is ignored rather than failing recovery.
func (j *Journal) Replay(fn func(*Record) error) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		for _, r := range j.mem {
			if err := fn(r); err != nil {
				return err
			}
		}
		return nil
	}
	if _, err := j.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	sc := bufio.NewScanner(j.f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			// torn tail from a crash: stop replay here
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}
		if err := fn(&r); err != nil {
			return err
		}
	}
	// return to append mode at end
	if _, err := j.f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	return nil
}

// Close flushes and closes the underlying file.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return nil
	}
	err := j.f.Close()
	j.f = nil
	return err
}
