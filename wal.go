package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WALEventType 是 WAL 事件类型。
type WALEventType string

const (
	WALGenCreated   WALEventType = "gen_created"
	WALGenActivated WALEventType = "gen_activated"
	WALGenRetired   WALEventType = "gen_retired"
	WALGenExpired   WALEventType = "gen_expired"
	WALCredIssued   WALEventType = "cred_issued"
	WALCredRevoked  WALEventType = "cred_revoked"
	WALCredRenewed  WALEventType = "cred_renewed"
	WALAudit        WALEventType = "audit"
)

// WALEvent 是追加写入的单条事件。
type WALEvent struct {
	Type      WALEventType     `json:"type"`
	Timestamp time.Time        `json:"timestamp"`
	Payload   json.RawMessage  `json:"payload"`
}

// GenCreatedPayload 是 gen_created 事件载荷。
type GenCreatedPayload struct {
	ID  int64  `json:"id"`
	Key []byte `json:"key"`
}

// GenActivatedPayload 是 gen_activated 事件载荷。
type GenActivatedPayload struct {
	ID          int64 `json:"id"`
	RetireAt    int64 `json:"retire_at"`     // 旧代次停止签发时间（0 表示无旧代次）
	ExpireAt    int64 `json:"expire_at"`     // 旧代次停止校验时间
}

// GenRetiredPayload 是 gen_retired 事件载荷。
type GenRetiredPayload struct {
	ID int64 `json:"id"`
}

// GenExpiredPayload 是 gen_expired 事件载荷。
type GenExpiredPayload struct {
	ID int64 `json:"id"`
}

// CredIssuedPayload 是 cred_issued 事件载荷。
type CredIssuedPayload struct {
	Credential
}

// CredRevokedPayload 是 cred_revoked 事件载荷。
type CredRevokedPayload struct {
	CredentialID string `json:"credential_id"`
	RevokedAt    int64  `json:"revoked_at"`
	ActorID      string `json:"actor_id"`
	ActorRole    string `json:"actor_role"`
}

// CredRenewedPayload 是 cred_renewed 事件载荷。
type CredRenewedPayload struct {
	CredentialID string `json:"credential_id"`
	NewNotAfter  int64  `json:"new_not_after"`
	Version      int64  `json:"version"`
	ActorID      string `json:"actor_id"`
	ActorRole    string `json:"actor_role"`
}

// AuditPayload 是 audit 事件载荷。
type AuditPayload struct {
	ID        int64  `json:"id"`
	Action    string `json:"action"`
	ActorID   string `json:"actor_id"`
	ActorRole string `json:"actor_role"`
	Success   bool   `json:"success"`
	Detail    string `json:"detail"`
}

// WAL 是追加式预写日志，所有变更先落盘再应用到内存。
type WAL struct {
	path string
	file *os.File
}

// NewWAL 创建或打开一个 WAL 文件（追加模式）。
func NewWAL(path string) (*WAL, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("wal: create dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("wal: open file: %w", err)
	}
	return &WAL{path: path, file: f}, nil
}

// Append 追加一条事件并落盘（fsync），保证持久化。
func (w *WAL) Append(event WALEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("wal: marshal event: %w", err)
	}
	data = append(data, '\n')
	if _, err := w.file.Write(data); err != nil {
		return fmt.Errorf("wal: write: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("wal: fsync: %w", err)
	}
	return nil
}

// Replay 重放所有事件，按顺序回调 handler。
func (w *WAL) Replay(handler func(WALEvent)) error {
	if _, err := w.file.Seek(0, 0); err != nil {
		return fmt.Errorf("wal: seek: %w", err)
	}
	scanner := bufio.NewScanner(w.file)
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var event WALEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return fmt.Errorf("wal: unmarshal event: %w", err)
		}
		handler(event)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("wal: scan: %w", err)
	}
	// 恢复到追加位置
	if _, err := w.file.Seek(0, 2); err != nil {
		return fmt.Errorf("wal: seek end: %w", err)
	}
	return nil
}

// Close 关闭 WAL 文件。
func (w *WAL) Close() error {
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}
