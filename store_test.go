package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// newTestStore 创建用于测试的 Store，使用临时目录。
func newTestStore(t *testing.T, config Config) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	config.DataDir = dir
	if config.TransitionWindow == 0 {
		config.TransitionWindow = 5 * time.Minute
	}
	if config.CredentialTTL == 0 {
		config.CredentialTTL = time.Hour
	}
	if config.MaxCredentialTTL == 0 {
		config.MaxCredentialTTL = 24 * time.Hour
	}
	if config.SweepInterval == 0 {
		config.SweepInterval = time.Minute
	}
	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	if err := store.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	return store, dir
}

func testActor(role Role) Actor {
	return Actor{ID: fmt.Sprintf("actor-%s", role), Role: role}
}

// --- 基本签发与校验 ---

func TestIssueAndVerify(t *testing.T) {
	store, _ := newTestStore(t, Config{})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)
	cred, err := store.Issue(ctx, actor, "service-a", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	if cred.ID == "" {
		t.Error("credential ID is empty")
	}
	if cred.GenerationID == 0 {
		t.Error("generation ID is 0")
	}

	if err := store.Verify(ctx, cred); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

// --- 过期凭证被拒绝 ---

func TestExpiredCredentialRejected(t *testing.T) {
	store, _ := newTestStore(t, Config{})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)
	cred, err := store.Issue(ctx, actor, "service-a", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	// 将租约的当前失效边界设为过去（模拟过期）
	store.mu.Lock()
	store.leases[cred.ID].NotAfter = time.Now().UTC().Add(-time.Hour)
	store.mu.Unlock()

	err = store.Verify(ctx, cred)
	if err == nil {
		t.Error("expected expired credential to be rejected")
	}
	ve, ok := err.(*VerifyError)
	if !ok {
		t.Fatalf("expected VerifyError, got %T", err)
	}
	if ve.Reason != VerifyExpired {
		t.Errorf("expected VerifyExpired, got %s", ve.Reason)
	}
}

// --- 伪造凭证被拒绝 ---

func TestForgedCredentialRejected(t *testing.T) {
	store, _ := newTestStore(t, Config{})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)
	cred, err := store.Issue(ctx, actor, "service-a", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// 篡改凭证内容
	cred.Subject = "forged-service"
	err = store.Verify(ctx, cred)
	if err == nil {
		t.Error("expected forged credential to be rejected")
	}
	ve, ok := err.(*VerifyError)
	if !ok {
		t.Fatalf("expected VerifyError, got %T", err)
	}
	if ve.Reason != VerifyForged {
		t.Errorf("expected VerifyForged, got %s", ve.Reason)
	}
}

// --- 吊销凭证被拒绝 ---

func TestRevokedCredentialRejected(t *testing.T) {
	store, _ := newTestStore(t, Config{})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)
	cred, err := store.Issue(ctx, actor, "service-a", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if err := store.Revoke(ctx, actor, cred.ID); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	err = store.Verify(ctx, cred)
	if err == nil {
		t.Error("expected revoked credential to be rejected")
	}
	ve, ok := err.(*VerifyError)
	if !ok {
		t.Fatalf("expected VerifyError, got %T", err)
	}
	if ve.Reason != VerifyRevoked {
		t.Errorf("expected VerifyRevoked, got %s", ve.Reason)
	}
}

// --- 失败原因可区分 ---

func TestFailureReasonsDistinguishable(t *testing.T) {
	store, _ := newTestStore(t, Config{})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)

	// 过期
	expired, _ := store.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
	store.mu.Lock()
	store.leases[expired.ID].NotAfter = time.Now().UTC().Add(-time.Hour)
	store.mu.Unlock()

	// 伪造
	forged, _ := store.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
	forged.Subject = "forged"

	// 吊销
	revoked, _ := store.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
	store.Revoke(ctx, actor, revoked.ID)

	// 未知代次
	unknown, _ := store.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
	unknown.GenerationID = 99999

	tests := []struct {
		name   string
		cred   *Credential
		reason VerifyFailureReason
	}{
		{"expired", expired, VerifyExpired},
		{"forged", forged, VerifyForged},
		{"revoked", revoked, VerifyRevoked},
		{"unknown_generation", unknown, VerifyUnknownGeneration},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Verify(ctx, tt.cred)
			if err == nil {
				t.Fatal("expected error")
			}
			ve, ok := err.(*VerifyError)
			if !ok {
				t.Fatalf("expected VerifyError, got %T", err)
			}
			if ve.Reason != tt.reason {
				t.Errorf("expected %s, got %s", tt.reason, ve.Reason)
			}
		})
	}
}

// --- 轮换过渡窗口 ---

func TestRotationTransitionWindow(t *testing.T) {
	store, _ := newTestStore(t, Config{TransitionWindow: 100 * time.Millisecond})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)

	// 轮换前签发的凭证
	oldCred, err := store.Issue(ctx, actor, "service-a", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// 执行轮换
	newGen, err := store.Rotate(ctx, actor)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	if newGen.ID == oldCred.GenerationID {
		t.Error("new generation ID should differ from old")
	}

	// 过渡窗口内：旧凭证仍可校验
	if err := store.Verify(ctx, oldCred); err != nil {
		t.Errorf("old credential should be valid during transition window: %v", err)
	}

	// 过渡窗口内：新凭证可签发（新代次）
	newCred, err := store.Issue(ctx, actor, "service-b", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue after rotate failed: %v", err)
	}
	if newCred.GenerationID != newGen.ID {
		t.Errorf("new credential should use new generation %d, got %d", newGen.ID, newCred.GenerationID)
	}

	// 等待过渡窗口结束
	time.Sleep(150 * time.Millisecond)
	store.sweep()

	// 窗口结束后：旧凭证仍可校验（按有效期自然失效，不被提前作废）
	if err := store.Verify(ctx, oldCred); err != nil {
		t.Errorf("old credential should still be valid after window (natural expiry): %v", err)
	}

	// 窗口结束后：旧代次不可签发（新凭证仍用新代次）
	newCred2, err := store.Issue(ctx, actor, "service-c", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue after window failed: %v", err)
	}
	if newCred2.GenerationID != newGen.ID {
		t.Errorf("after window, should still sign with new generation %d, got %d", newGen.ID, newCred2.GenerationID)
	}
}

// --- 轮换原子性：读取方不见混合状态 ---

func TestRotationAtomicity(t *testing.T) {
	store, _ := newTestStore(t, Config{})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)

	// 并发轮换与校验，校验方不应看到半新半旧状态
	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cred, err := store.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
			if err != nil {
				errCh <- err
				return
			}
			if err := store.Verify(ctx, cred); err != nil {
				errCh <- err
			}
		}()
	}

	// 并发轮换
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Rotate(ctx, actor); err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent operation error: %v", err)
	}

	// 校验所有代次状态一致：activeGenID 指向的代次必须是 Active 或 Retiring
	gens, _ := store.ListGenerations(ctx)
	activeCount := 0
	for _, g := range gens {
		if g.ID == store.activeGenID {
			activeCount++
			if g.Status != GenActive && g.Status != GenRetiring {
				t.Errorf("active generation %d has unexpected status %s", g.ID, g.Status)
			}
		}
	}
	if activeCount != 1 {
		t.Errorf("expected exactly 1 active generation, got %d", activeCount)
	}
}

// --- 并发签发与轮换 ---

func TestConcurrentIssueAndRotate(t *testing.T) {
	store, _ := newTestStore(t, Config{})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)

	var wg sync.WaitGroup
	errCh := make(chan error, 200)

	// 并发签发
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
			if err != nil {
				errCh <- err
			}
		}()
	}

	// 并发轮换
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Rotate(ctx, actor)
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent error: %v", err)
	}
}

// --- 吊销与续期竞争 ---

func TestConcurrentRevokeAndRenew(t *testing.T) {
	store, _ := newTestStore(t, Config{})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)
	cred, err := store.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	var wg sync.WaitGroup
	// 并发续期
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			newNotAfter := time.Now().UTC().Add(time.Duration(i+1) * time.Hour)
			_, _ = store.Renew(ctx, actor, cred.ID, newNotAfter)
		}(i)
	}
	// 并发吊销
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = store.Revoke(ctx, actor, cred.ID)
		}()
	}

	wg.Wait()

	// 最终状态一致：要么已吊销，要么未吊销且租约有效
	lease := store.leases[cred.ID]
	if lease == nil {
		t.Fatal("lease not found")
	}
	// 吊销后校验必须失败
	if lease.Revoked {
		if err := store.Verify(ctx, cred); err == nil {
			t.Error("revoked credential should be rejected")
		}
	}
}

// --- 续期不可越过代次生命周期 ---

func TestRenewExceedsGenerationLifecycle(t *testing.T) {
	store, _ := newTestStore(t, Config{MaxCredentialTTL: time.Hour})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)
	cred, err := store.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// 续期到代次生命周期之后（MaxCredentialTTL=1h，代次 ExpiredAt 更远）
	// 先轮换，让旧代次进入 Retiring 并设置 ExpiredAt
	_, err = store.Rotate(ctx, actor)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	// 尝试续期到远超代次生命周期的时间
	gen := store.generations[cred.GenerationID]
	farFuture := gen.ExpiredAt.Add(24 * time.Hour)
	_, err = store.Renew(ctx, actor, cred.ID, farFuture)
	if err == nil {
		t.Error("expected renewal exceeding generation lifecycle to fail")
	}
}

// --- 越权请求被拒绝 ---

func TestUnauthorizedRequestRejected(t *testing.T) {
	store, _ := newTestStore(t, Config{})
	defer store.Stop()

	ctx := context.Background()

	// verifier 不能签发
	verifier := testActor(RoleVerifier)
	_, err := store.Issue(ctx, verifier, "s", RoleIssuer, time.Hour)
	if err == nil {
		t.Error("verifier should not be allowed to issue")
	}
	if _, ok := err.(*AuthError); !ok {
		t.Errorf("expected AuthError, got %T", err)
	}

	// issuer 不能轮换
	issuer := testActor(RoleIssuer)
	_, err = store.Rotate(ctx, issuer)
	if err == nil {
		t.Error("issuer should not be allowed to rotate")
	}
	if _, ok := err.(*AuthError); !ok {
		t.Errorf("expected AuthError, got %T", err)
	}

	// 检查审计记录包含越权失败
	records, _ := store.GetAuditLog(ctx)
	found := false
	for _, r := range records {
		if !r.Success && r.Action == ActionIssue {
			found = true
		}
	}
	if !found {
		t.Error("audit should record unauthorized issue attempt")
	}
}

// --- 审计记录完整 ---

func TestAuditRecords(t *testing.T) {
	store, _ := newTestStore(t, Config{})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)

	cred, _ := store.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
	store.Rotate(ctx, actor)
	store.Revoke(ctx, actor, cred.ID)

	records, err := store.GetAuditLog(ctx)
	if err != nil {
		t.Fatalf("GetAuditLog failed: %v", err)
	}

	actions := make(map[Action]int)
	for _, r := range records {
		actions[r.Action]++
		if r.ActorID == "" {
			t.Error("audit record missing actor ID")
		}
	}

	if actions[ActionIssue] < 1 {
		t.Error("missing issue audit record")
	}
	if actions[ActionRotate] < 1 {
		t.Error("missing rotate audit record")
	}
	if actions[ActionRevoke] < 1 {
		t.Error("missing revoke audit record")
	}
}

// --- 重启恢复：已提交代次与吊销状态存活 ---

func TestRestartRecovery(t *testing.T) {
	dir := t.TempDir()
	config := DefaultConfig()
	config.DataDir = dir

	// 第一个进程：签发、轮换、吊销
	store1, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	if err := store1.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	ctx := context.Background()
	actor := testActor(RoleAdmin)
	cred, err := store1.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	_, err = store1.Rotate(ctx, actor)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	if err := store1.Revoke(ctx, actor, cred.ID); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// 记录重启前的状态
	gensBefore, _ := store1.ListGenerations(ctx)
	auditBefore, _ := store1.GetAuditLog(ctx)

	store1.Stop()

	// 第二个进程：恢复
	store2, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore (2) failed: %v", err)
	}
	if err := store2.Start(); err != nil {
		t.Fatalf("Start (2) failed: %v", err)
	}
	defer store2.Stop()

	// 代次恢复
	gensAfter, _ := store2.ListGenerations(ctx)
	if len(gensAfter) != len(gensBefore) {
		t.Errorf("generation count mismatch: before=%d after=%d", len(gensBefore), len(gensAfter))
	}

	// 吊销状态恢复：凭证仍被拒绝
	if err := store2.Verify(ctx, cred); err == nil {
		t.Error("revoked credential should still be rejected after restart")
	} else {
		ve, ok := err.(*VerifyError)
		if !ok || ve.Reason != VerifyRevoked {
			t.Errorf("expected VerifyRevoked after restart, got %v", err)
		}
	}

	// 审计记录恢复
	auditAfter, _ := store2.GetAuditLog(ctx)
	if len(auditAfter) < len(auditBefore) {
		t.Errorf("audit records lost after restart: before=%d after=%d", len(auditBefore), len(auditAfter))
	}

	// 新进程可正常签发
	newCred, err := store2.Issue(ctx, actor, "s2", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue after restart failed: %v", err)
	}
	if err := store2.Verify(ctx, newCred); err != nil {
		t.Errorf("new credential after restart should be valid: %v", err)
	}
}

// --- 重启恢复：未完成轮换恢复到一致状态 ---

func TestIncompleteRotationRecovery(t *testing.T) {
	dir := t.TempDir()
	config := DefaultConfig()
	config.DataDir = dir

	store1, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	if err := store1.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	ctx := context.Background()
	actor := testActor(RoleAdmin)

	// 手动模拟未完成轮换：直接写入 gen_created 事件但不写 gen_activated
	// 先正常签发一个凭证
	cred, err := store1.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// 手动追加一个 gen_created 事件（模拟轮换中途崩溃）
	store1.mu.Lock()
	newKey := make([]byte, 32)
	genID := store1.nextGenID
	store1.nextGenID++
	payload, _ := json.Marshal(GenCreatedPayload{ID: genID, Key: newKey})
	store1.wal.Append(WALEvent{
		Type:      WALGenCreated,
		Timestamp: time.Now().UTC(),
		Payload:   payload,
	})
	store1.mu.Unlock()

	store1.Stop()

	// 重启恢复
	store2, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore (2) failed: %v", err)
	}
	if err := store2.Start(); err != nil {
		t.Fatalf("Start (2) failed: %v", err)
	}
	defer store2.Stop()

	// 恢复后应有活跃代次，且服务可正常签发
	newCred, err := store2.Issue(ctx, actor, "s2", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue after recovery failed: %v", err)
	}
	if err := store2.Verify(ctx, newCred); err != nil {
		t.Errorf("credential after recovery should be valid: %v", err)
	}

	// 旧凭证仍可校验
	if err := store2.Verify(ctx, cred); err != nil {
		t.Errorf("old credential should still be valid after recovery: %v", err)
	}

	// 不应有多个活跃代次
	gens, _ := store2.ListGenerations(ctx)
	activeCount := 0
	for _, g := range gens {
		if g.Status == GenActive {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Errorf("expected 1 active generation after recovery, got %d", activeCount)
	}
}

// --- 续期正常流程 ---

func TestRenewCredential(t *testing.T) {
	store, _ := newTestStore(t, Config{})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)
	cred, err := store.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// 续期
	newNotAfter := time.Now().UTC().Add(2 * time.Hour)
	lease, err := store.Renew(ctx, actor, cred.ID, newNotAfter)
	if err != nil {
		t.Fatalf("Renew failed: %v", err)
	}
	if !lease.NotAfter.Equal(newNotAfter) {
		t.Errorf("renewed NotAfter mismatch: got %v, want %v", lease.NotAfter, newNotAfter)
	}
	if lease.Version != 1 {
		t.Errorf("expected version 1, got %d", lease.Version)
	}

	// 续期后凭证仍可校验
	if err := store.Verify(ctx, cred); err != nil {
		t.Errorf("renewed credential should be valid: %v", err)
	}

	// 吊销后续期失败
	store.Revoke(ctx, actor, cred.ID)
	_, err = store.Renew(ctx, actor, cred.ID, time.Now().UTC().Add(3*time.Hour))
	if err == nil {
		t.Error("renewal after revocation should fail")
	}
}

// --- 凭证不早于生效边界 ---

func TestNotBeforeBoundary(t *testing.T) {
	store, _ := newTestStore(t, Config{})
	defer store.Stop()

	ctx := context.Background()
	actor := testActor(RoleAdmin)
	cred, err := store.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// 将 NotBefore 设为未来
	cred.NotBefore = time.Now().UTC().Add(time.Hour)
	gen := store.generations[cred.GenerationID]
	cred.sign(gen.Key)

	err = store.Verify(ctx, cred)
	if err == nil {
		t.Error("expected not-yet-valid credential to be rejected")
	}
	ve, ok := err.(*VerifyError)
	if !ok {
		t.Fatalf("expected VerifyError, got %T", err)
	}
	if ve.Reason != VerifyNotYetValid {
		t.Errorf("expected VerifyNotYetValid, got %s", ve.Reason)
	}
}

// --- WAL 文件持久化 ---

func TestWALPersistence(t *testing.T) {
	dir := t.TempDir()
	config := DefaultConfig()
	config.DataDir = dir

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	if err := store.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	ctx := context.Background()
	actor := testActor(RoleAdmin)
	store.Issue(ctx, actor, "s", RoleIssuer, time.Hour)
	store.Rotate(ctx, actor)
	store.Stop()

	// 检查 WAL 文件存在且非空
	walPath := filepath.Join(dir, "wal.log")
	info, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("WAL file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Error("WAL file is empty")
	}
}
