package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Store 是密钥轮换与凭证发放服务的核心，所有操作在本地进程内完成。
type Store struct {
	mu     sync.RWMutex
	config Config
	wal    *WAL
	audit  *AuditLog

	generations map[int64]*KeyGeneration
	activeGenID int64
	leases      map[string]*Lease
	nextGenID   int64
	nextAuditID int64

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewStore 创建服务实例。
func NewStore(config Config) (*Store, error) {
	if config.DataDir == "" {
		config = DefaultConfig()
	}
	return &Store{
		config:      config,
		generations: make(map[int64]*KeyGeneration),
		leases:      make(map[string]*Lease),
		audit:       NewAuditLog(),
		stopCh:      make(chan struct{}),
		nextGenID:   1, // 代次 ID 从 1 开始，0 表示无活跃代次
	}, nil
}

// Start 启动服务：重放 WAL 恢复状态，恢复未完成轮换，启动后台清理。
func (s *Store) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	walPath := s.config.DataDir + "/wal.log"
	wal, err := NewWAL(walPath)
	if err != nil {
		return fmt.Errorf("store: open wal: %w", err)
	}
	s.wal = wal

	if err := s.replay(); err != nil {
		return fmt.Errorf("store: replay: %w", err)
	}

	// 恢复未完成轮换（已创建但未提交的代次）
	if err := s.recoverPendingRotations(); err != nil {
		return fmt.Errorf("store: recover: %w", err)
	}

	// 若无任何代次，创建首个代次
	if s.activeGenID == 0 {
		if err := s.createInitialGeneration(); err != nil {
			return fmt.Errorf("store: initial generation: %w", err)
		}
	}

	// 启动后台清理协程
	s.stopCh = make(chan struct{})
	s.wg.Add(1)
	go s.sweepLoop()

	return nil
}

// Stop 停止服务。
func (s *Store) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopCh != nil {
		close(s.stopCh)
		s.wg.Wait()
		s.stopCh = nil
	}
	if s.wal != nil {
		if err := s.wal.Close(); err != nil {
			return err
		}
		s.wal = nil
	}
	return nil
}

// replay 重放 WAL 事件重建内存状态。
func (s *Store) replay() error {
	return s.wal.Replay(func(event WALEvent) {
		switch event.Type {
		case WALGenCreated:
			var p GenCreatedPayload
			if err := json.Unmarshal(event.Payload, &p); err != nil {
				return
			}
			s.generations[p.ID] = &KeyGeneration{
				ID:        p.ID,
				Key:       p.Key,
				Status:    GenPending,
				CreatedAt: event.Timestamp,
			}
			if p.ID >= s.nextGenID {
				s.nextGenID = p.ID + 1
			}
		case WALGenActivated:
			var p GenActivatedPayload
			if err := json.Unmarshal(event.Payload, &p); err != nil {
				return
			}
			gen, ok := s.generations[p.ID]
			if !ok {
				return
			}
			gen.Status = GenActive
			gen.ActivatedAt = event.Timestamp
			// 旧代次处理
			if s.activeGenID != 0 && s.activeGenID != p.ID {
				if old, ok := s.generations[s.activeGenID]; ok {
					old.Status = GenRetiring
					if p.RetireAt > 0 {
						old.RetiredAt = time.Unix(0, p.RetireAt)
					}
					if p.ExpireAt > 0 {
						old.ExpiredAt = time.Unix(0, p.ExpireAt)
					}
				}
			}
			s.activeGenID = p.ID
		case WALGenRetired:
			var p GenRetiredPayload
			if err := json.Unmarshal(event.Payload, &p); err != nil {
				return
			}
			if gen, ok := s.generations[p.ID]; ok {
				gen.Status = GenRetired
				gen.RetiredAt = event.Timestamp
			}
		case WALGenExpired:
			var p GenExpiredPayload
			if err := json.Unmarshal(event.Payload, &p); err != nil {
				return
			}
			if gen, ok := s.generations[p.ID]; ok {
				gen.Status = GenExpired
				gen.ExpiredAt = event.Timestamp
			}
		case WALCredIssued:
			var p CredIssuedPayload
			if err := json.Unmarshal(event.Payload, &p); err != nil {
				return
			}
			s.leases[p.ID] = &Lease{
				CredentialID: p.ID,
				GenerationID: p.GenerationID,
				Subject:      p.Subject,
				Role:         p.Role,
				IssuedAt:     p.IssuedAt,
				NotBefore:    p.NotBefore,
				NotAfter:     p.NotAfter,
				Renewable:    p.Renewable,
			}
		case WALCredRevoked:
			var p CredRevokedPayload
			if err := json.Unmarshal(event.Payload, &p); err != nil {
				return
			}
			if lease, ok := s.leases[p.CredentialID]; ok {
				lease.Revoked = true
				lease.RevokedAt = time.Unix(0, p.RevokedAt)
			}
		case WALCredRenewed:
			var p CredRenewedPayload
			if err := json.Unmarshal(event.Payload, &p); err != nil {
				return
			}
			if lease, ok := s.leases[p.CredentialID]; ok {
				lease.NotAfter = time.Unix(0, p.NewNotAfter)
				lease.Version = p.Version
			}
		case WALAudit:
			var p AuditPayload
			if err := json.Unmarshal(event.Payload, &p); err != nil {
				return
			}
			s.audit.Record(AuditRecord{
				ID:        p.ID,
				Timestamp: event.Timestamp,
				Action:    Action(p.Action),
				ActorID:   p.ActorID,
				ActorRole: Role(p.ActorRole),
				Success:   p.Success,
				Detail:    p.Detail,
			})
			if p.ID >= s.nextAuditID {
				s.nextAuditID = p.ID + 1
			}
		}
	})
}

// recoverPendingRotations 恢复未完成轮换：已创建但未提交的代次，提交为活跃代次。
// 已提交代次与未完成轮换通过事件类型区分，恢复后达到一致状态，不重复签发。
func (s *Store) recoverPendingRotations() error {
	var pending []*KeyGeneration
	for _, gen := range s.generations {
		if gen.Status == GenPending {
			pending = append(pending, gen)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	// 取最新的待提交代次提交，其余标记为废弃（不暴露）
	var latest *KeyGeneration
	for _, gen := range pending {
		if latest == nil || gen.ID > latest.ID {
			latest = gen
		}
	}
	now := time.Now().UTC()
	retireAt := now.Add(s.config.TransitionWindow)
	expireAt := retireAt.Add(s.config.MaxCredentialTTL)

	// 提交最新代次
	payload, err := json.Marshal(GenActivatedPayload{
		ID:       latest.ID,
		RetireAt: retireAt.UnixNano(),
		ExpireAt: expireAt.UnixNano(),
	})
	if err != nil {
		return err
	}
	if err := s.wal.Append(WALEvent{
		Type:      WALGenActivated,
		Timestamp: now,
		Payload:   payload,
	}); err != nil {
		return err
	}
	latest.Status = GenActive
	latest.ActivatedAt = now
	if s.activeGenID != 0 && s.activeGenID != latest.ID {
		if old, ok := s.generations[s.activeGenID]; ok {
			old.Status = GenRetiring
			old.RetiredAt = retireAt
			old.ExpiredAt = expireAt
		}
	}
	s.activeGenID = latest.ID

	// 其余待提交代次标记为 Expired（废弃，不暴露）
	for _, gen := range pending {
		if gen.ID == latest.ID {
			continue
		}
		gen.Status = GenExpired
		gen.ExpiredAt = now
	}
	return nil
}

// createInitialGeneration 创建首个代次并提交。
func (s *Store) createInitialGeneration() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	genID := s.nextGenID
	s.nextGenID++
	now := time.Now().UTC()

	payload, err := json.Marshal(GenCreatedPayload{ID: genID, Key: key})
	if err != nil {
		return err
	}
	if err := s.wal.Append(WALEvent{
		Type:      WALGenCreated,
		Timestamp: now,
		Payload:   payload,
	}); err != nil {
		return err
	}

	gen := &KeyGeneration{
		ID:        genID,
		Key:       key,
		Status:    GenActive,
		CreatedAt: now,
		ActivatedAt: now,
	}
	s.generations[genID] = gen
	s.activeGenID = genID

	// 提交事件
	actPayload, err := json.Marshal(GenActivatedPayload{ID: genID})
	if err != nil {
		return err
	}
	if err := s.wal.Append(WALEvent{
		Type:      WALGenActivated,
		Timestamp: now,
		Payload:   actPayload,
	}); err != nil {
		return err
	}

	s.recordAuditLocked(ActionRotate, Actor{ID: "system", Role: RoleAdmin}, true, "initial generation created")
	return nil
}

// Issue 签发短时凭证。
func (s *Store) Issue(ctx context.Context, actor Actor, subject string, role Role, ttl time.Duration) (*Credential, error) {
	if !canPerform(actor.Role, ActionIssue) {
		s.recordAudit(ActionIssue, actor, false, "permission denied")
		return nil, &AuthError{Actor: actor.ID, Role: actor.Role, Action: string(ActionIssue)}
	}
	if ttl <= 0 {
		ttl = s.config.CredentialTTL
	}
	if ttl > s.config.MaxCredentialTTL {
		ttl = s.config.MaxCredentialTTL
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	gen, err := s.activeSigningGenerationLocked(time.Now().UTC())
	if err != nil {
		s.recordAuditLocked(ActionIssue, actor, false, err.Error())
		return nil, err
	}

	credID := generateID()
	now := time.Now().UTC()
	cred := &Credential{
		ID:           credID,
		GenerationID: gen.ID,
		Subject:      subject,
		Role:         role,
		IssuedAt:     now,
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
		Renewable:    true,
	}
	if err := cred.sign(gen.Key); err != nil {
		s.recordAuditLocked(ActionIssue, actor, false, err.Error())
		return nil, err
	}

	// 持久化
	payload, err := json.Marshal(CredIssuedPayload{Credential: *cred})
	if err != nil {
		s.recordAuditLocked(ActionIssue, actor, false, err.Error())
		return nil, err
	}
	if err := s.wal.Append(WALEvent{
		Type:      WALCredIssued,
		Timestamp: now,
		Payload:   payload,
	}); err != nil {
		s.recordAuditLocked(ActionIssue, actor, false, err.Error())
		return nil, err
	}

	s.leases[credID] = &Lease{
		CredentialID: credID,
		GenerationID: gen.ID,
		Subject:      subject,
		Role:         role,
		IssuedAt:     now,
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
		Renewable:    true,
	}

	s.recordAuditLocked(ActionIssue, actor, true, fmt.Sprintf("credential=%s generation=%d", credID, gen.ID))
	return cred, nil
}

// Verify 校验凭证，失败原因可区分。
func (s *Store) Verify(ctx context.Context, cred *Credential) error {
	if cred == nil {
		return &VerifyError{Reason: VerifyForged, Detail: "nil credential"}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	gen, ok := s.generations[cred.GenerationID]
	if !ok {
		return &VerifyError{Reason: VerifyUnknownGeneration, Detail: fmt.Sprintf("generation %d not found", cred.GenerationID)}
	}
	now := time.Now().UTC()
	if !gen.canVerify(now) {
		return &VerifyError{Reason: VerifyGenerationExpired, Detail: fmt.Sprintf("generation %d expired", cred.GenerationID)}
	}

	// 校验签名（防伪造）
	if !cred.verifySignature(gen.Key) {
		return &VerifyError{Reason: VerifyForged, Detail: "signature mismatch"}
	}

	// 校验生效边界（NotBefore 不随续期改变）
	if now.Before(cred.NotBefore) {
		return &VerifyError{Reason: VerifyNotYetValid, Detail: "not before"}
	}

	// 校验租约状态（吊销 + 当前失效边界）
	lease, ok := s.leases[cred.ID]
	if !ok {
		return &VerifyError{Reason: VerifyForged, Detail: "lease not found"}
	}
	if lease.Revoked {
		return &VerifyError{Reason: VerifyRevoked, Detail: fmt.Sprintf("revoked at %v", lease.RevokedAt)}
	}
	// 失效边界以租约当前 NotAfter 为准（续期后已延长）
	if now.After(lease.NotAfter) {
		return &VerifyError{Reason: VerifyExpired, Detail: "lease expired"}
	}

	return nil
}

// Rotate 轮换主密钥，返回新代次。
func (s *Store) Rotate(ctx context.Context, actor Actor) (*KeyGeneration, error) {
	if !canPerform(actor.Role, ActionRotate) {
		s.recordAudit(ActionRotate, actor, false, "permission denied")
		return nil, &AuthError{Actor: actor.ID, Role: actor.Role, Action: string(ActionRotate)}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	// 1. 生成新主密钥
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		s.recordAuditLocked(ActionRotate, actor, false, err.Error())
		return nil, &RotationError{Phase: "generate", Err: err}
	}
	newGenID := s.nextGenID
	s.nextGenID++

	// 2. 持久化新代次（Pending）—— 已提交代次与未完成轮换的分界点
	createdPayload, err := json.Marshal(GenCreatedPayload{ID: newGenID, Key: newKey})
	if err != nil {
		s.recordAuditLocked(ActionRotate, actor, false, err.Error())
		return nil, &RotationError{Phase: "marshal", Err: err}
	}
	if err := s.wal.Append(WALEvent{
		Type:      WALGenCreated,
		Timestamp: now,
		Payload:   createdPayload,
	}); err != nil {
		s.recordAuditLocked(ActionRotate, actor, false, err.Error())
		return nil, &RotationError{Phase: "persist_created", Err: err}
	}

	// 3. 原子提交：新代次 Activated，旧代次 Retiring
	retireAt := now.Add(s.config.TransitionWindow)
	expireAt := retireAt.Add(s.config.MaxCredentialTTL)
	actPayload, err := json.Marshal(GenActivatedPayload{
		ID:       newGenID,
		RetireAt: retireAt.UnixNano(),
		ExpireAt: expireAt.UnixNano(),
	})
	if err != nil {
		s.recordAuditLocked(ActionRotate, actor, false, err.Error())
		return nil, &RotationError{Phase: "marshal_activate", Err: err}
	}
	if err := s.wal.Append(WALEvent{
		Type:      WALGenActivated,
		Timestamp: now,
		Payload:   actPayload,
	}); err != nil {
		s.recordAuditLocked(ActionRotate, actor, false, err.Error())
		return nil, &RotationError{Phase: "persist_activate", Err: err}
	}

	// 4. 更新内存状态（原子切换，读取方只见完整代次）
	newGen := &KeyGeneration{
		ID:          newGenID,
		Key:         newKey,
		Status:      GenActive,
		CreatedAt:   now,
		ActivatedAt: now,
	}
	s.generations[newGenID] = newGen

	if s.activeGenID != 0 && s.activeGenID != newGenID {
		if old, ok := s.generations[s.activeGenID]; ok {
			old.Status = GenRetiring
			old.RetiredAt = retireAt
			old.ExpiredAt = expireAt
		}
	}
	s.activeGenID = newGenID

	s.recordAuditLocked(ActionRotate, actor, true, fmt.Sprintf("new_generation=%d", newGenID))
	return newGen, nil
}

// Revoke 吊销凭证，立即生效。
func (s *Store) Revoke(ctx context.Context, actor Actor, credentialID string) error {
	if !canPerform(actor.Role, ActionRevoke) {
		s.recordAudit(ActionRevoke, actor, false, "permission denied")
		return &AuthError{Actor: actor.ID, Role: actor.Role, Action: string(ActionRevoke)}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	lease, ok := s.leases[credentialID]
	if !ok {
		s.recordAuditLocked(ActionRevoke, actor, false, "credential not found")
		return &LeaseError{CredentialID: credentialID, Operation: "revoke", Err: fmt.Errorf("credential not found")}
	}
	if lease.Revoked {
		s.recordAuditLocked(ActionRevoke, actor, true, "already revoked")
		return nil
	}

	now := time.Now().UTC()
	payload, err := json.Marshal(CredRevokedPayload{
		CredentialID: credentialID,
		RevokedAt:    now.UnixNano(),
		ActorID:      actor.ID,
		ActorRole:    string(actor.Role),
	})
	if err != nil {
		s.recordAuditLocked(ActionRevoke, actor, false, err.Error())
		return err
	}
	if err := s.wal.Append(WALEvent{
		Type:      WALCredRevoked,
		Timestamp: now,
		Payload:   payload,
	}); err != nil {
		s.recordAuditLocked(ActionRevoke, actor, false, err.Error())
		return err
	}

	lease.Revoked = true
	lease.RevokedAt = now

	s.recordAuditLocked(ActionRevoke, actor, true, fmt.Sprintf("credential=%s", credentialID))
	return nil
}

// Renew 续期租约，不得越过所在代次生命周期。
func (s *Store) Renew(ctx context.Context, actor Actor, credentialID string, newNotAfter time.Time) (*Lease, error) {
	if !canPerform(actor.Role, ActionRenew) {
		s.recordAudit(ActionRenew, actor, false, "permission denied")
		return nil, &AuthError{Actor: actor.ID, Role: actor.Role, Action: string(ActionRenew)}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	lease, ok := s.leases[credentialID]
	if !ok {
		s.recordAuditLocked(ActionRenew, actor, false, "credential not found")
		return nil, &LeaseError{CredentialID: credentialID, Operation: "renew", Err: fmt.Errorf("credential not found")}
	}
	if lease.Revoked {
		s.recordAuditLocked(ActionRenew, actor, false, "credential revoked")
		return nil, &LeaseError{CredentialID: credentialID, Operation: "renew", Err: fmt.Errorf("credential revoked")}
	}
	if !lease.Renewable {
		s.recordAuditLocked(ActionRenew, actor, false, "not renewable")
		return nil, &LeaseError{CredentialID: credentialID, Operation: "renew", Err: fmt.Errorf("not renewable")}
	}

	gen, ok := s.generations[lease.GenerationID]
	if !ok {
		s.recordAuditLocked(ActionRenew, actor, false, "generation not found")
		return nil, &LeaseError{CredentialID: credentialID, Operation: "renew", Err: fmt.Errorf("generation not found")}
	}
	now := time.Now().UTC()
	if !gen.canVerify(now) {
		s.recordAuditLocked(ActionRenew, actor, false, "generation expired")
		return nil, &LeaseError{CredentialID: credentialID, Operation: "renew", Err: fmt.Errorf("generation expired")}
	}

	// 续期不得越过所在代次生命周期
	if !gen.ExpiredAt.IsZero() && newNotAfter.After(gen.ExpiredAt) {
		s.recordAuditLocked(ActionRenew, actor, false, "exceeds generation lifecycle")
		return nil, &LeaseError{CredentialID: credentialID, Operation: "renew", Err: fmt.Errorf("new not_after %v exceeds generation lifecycle %v", newNotAfter, gen.ExpiredAt)}
	}
	// 续期不得早于当前失效边界
	if !newNotAfter.After(lease.NotAfter) {
		s.recordAuditLocked(ActionRenew, actor, false, "new not_after must be later")
		return nil, &LeaseError{CredentialID: credentialID, Operation: "renew", Err: fmt.Errorf("new not_after must be later than current")}
	}

	newVersion := lease.Version + 1
	payload, err := json.Marshal(CredRenewedPayload{
		CredentialID: credentialID,
		NewNotAfter:  newNotAfter.UnixNano(),
		Version:      newVersion,
		ActorID:      actor.ID,
		ActorRole:    string(actor.Role),
	})
	if err != nil {
		s.recordAuditLocked(ActionRenew, actor, false, err.Error())
		return nil, err
	}
	if err := s.wal.Append(WALEvent{
		Type:      WALCredRenewed,
		Timestamp: now,
		Payload:   payload,
	}); err != nil {
		s.recordAuditLocked(ActionRenew, actor, false, err.Error())
		return nil, err
	}

	lease.NotAfter = newNotAfter
	lease.Version = newVersion

	s.recordAuditLocked(ActionRenew, actor, true, fmt.Sprintf("credential=%s new_not_after=%v version=%d", credentialID, newNotAfter, newVersion))
	return lease, nil
}

// ListGenerations 返回所有代次快照。
func (s *Store) ListGenerations(ctx context.Context) ([]*KeyGeneration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*KeyGeneration, 0, len(s.generations))
	for _, gen := range s.generations {
		cp := *gen
		cp.Key = nil // 不暴露密钥
		result = append(result, &cp)
	}
	return result, nil
}

// GetAuditLog 返回审计记录。
func (s *Store) GetAuditLog(ctx context.Context) ([]AuditRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := s.audit.Records()
	result := make([]AuditRecord, len(records))
	copy(result, records)
	return result, nil
}

// --- 内部辅助方法 ---

// activeSigningGenerationLocked 返回当前可签发的代次（持锁）。
func (s *Store) activeSigningGenerationLocked(now time.Time) (*KeyGeneration, error) {
	if s.activeGenID == 0 {
		return nil, fmt.Errorf("no active generation")
	}
	gen, ok := s.generations[s.activeGenID]
	if !ok {
		return nil, fmt.Errorf("active generation %d not found", s.activeGenID)
	}
	if !gen.canSign(now) {
		// 活跃代次不可签发，检查是否有 Retiring 代次可签发
		for _, g := range s.generations {
			if g.canSign(now) {
				return g, nil
			}
		}
		return nil, fmt.Errorf("no signing generation available")
	}
	return gen, nil
}

// recordAudit 记录审计（无锁版本，内部加锁）。
func (s *Store) recordAudit(action Action, actor Actor, success bool, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordAuditLocked(action, actor, success, detail)
}

// recordAuditLocked 记录审计（持锁版本），持久化到 WAL。
func (s *Store) recordAuditLocked(action Action, actor Actor, success bool, detail string) {
	id := s.nextAuditID
	s.nextAuditID++
	rec := AuditRecord{
		ID:        id,
		Timestamp: time.Now().UTC(),
		Action:    action,
		ActorID:   actor.ID,
		ActorRole: actor.Role,
		Success:   success,
		Detail:    detail,
	}
	s.audit.Record(rec)

	// 持久化审计记录
	if s.wal != nil {
		payload, _ := json.Marshal(AuditPayload{
			ID:        id,
			Action:    string(action),
			ActorID:   actor.ID,
			ActorRole: string(actor.Role),
			Success:   success,
			Detail:    detail,
		})
		_ = s.wal.Append(WALEvent{
			Type:      WALAudit,
			Timestamp: rec.Timestamp,
			Payload:   payload,
		})
	}
}

// sweepLoop 后台循环：清理过期代次。
func (s *Store) sweepLoop() {
	defer s.wg.Done()
	interval := s.config.SweepInterval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.sweep()
		}
	}
}

// sweep 执行一次代次清理。
func (s *Store) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for _, gen := range s.generations {
		switch gen.Status {
		case GenRetiring:
			if !now.Before(gen.RetiredAt) {
				// 过渡窗口结束，转为 Retired
				payload, _ := json.Marshal(GenRetiredPayload{ID: gen.ID})
				if err := s.wal.Append(WALEvent{
					Type:      WALGenRetired,
					Timestamp: now,
					Payload:   payload,
				}); err == nil {
					gen.Status = GenRetired
					gen.RetiredAt = now
				}
			}
		case GenRetired:
			if !now.Before(gen.ExpiredAt) {
				// 代次过期，转为 Expired
				payload, _ := json.Marshal(GenExpiredPayload{ID: gen.ID})
				if err := s.wal.Append(WALEvent{
					Type:      WALGenExpired,
					Timestamp: now,
					Payload:   payload,
				}); err == nil {
					gen.Status = GenExpired
					gen.ExpiredAt = now
				}
			}
		}
	}
}

// generateID 生成唯一凭证 ID。
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("cred-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("cred-%x", b)
}
