package main

import "time"

// Lease 是凭证的服务端租约状态，用于吊销与续期。
type Lease struct {
	CredentialID string
	GenerationID int64
	Subject      string
	Role         Role
	IssuedAt     time.Time
	NotBefore    time.Time
	NotAfter     time.Time // 当前失效边界（续期可延长）
	Renewable    bool
	Revoked      bool
	RevokedAt    time.Time
	Version      int64 // 乐观并发版本
}
