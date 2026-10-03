package main

import (
	"sync"
	"time"
)

// AuditRecord 是一条可核验的审计记录。
type AuditRecord struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    Action    `json:"action"`
	ActorID   string    `json:"actor_id"`
	ActorRole Role      `json:"actor_role"`
	Success   bool      `json:"success"`
	Detail    string    `json:"detail"`
}

// AuditLog 是追加式审计日志。
type AuditLog struct {
	mu      sync.RWMutex
	records []AuditRecord
}

// NewAuditLog 创建审计日志。
func NewAuditLog() *AuditLog {
	return &AuditLog{}
}

// Record 追加一条审计记录。
func (a *AuditLog) Record(rec AuditRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, rec)
}

// Records 返回所有审计记录的副本。
func (a *AuditLog) Records() []AuditRecord {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]AuditRecord, len(a.records))
	copy(result, a.records)
	return result
}
