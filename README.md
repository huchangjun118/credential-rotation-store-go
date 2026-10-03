# 密钥轮换与短时凭证发放服务

一套本地可运行的密钥轮换与短时凭证发放服务。服务向下游按需签发带有效期的凭证，底层主密钥定期轮换，轮换过程中不中断在用凭证，读取方不会看到半新半旧的混合状态。签发、校验、吊销与轮换均在本地进程内完成，不依赖外部服务。

## 核心特性

- **基于主密钥派生签发**：使用 HKDF-like 派生函数从主密钥派生发密钥，HMAC-SHA256 签名
- **明确的凭证有效期**：凭证携带 NotBefore（生效边界）与 NotAfter（失效边界）
- **可区分的失败原因**：过期、伪造、已吊销、未生效、代次过期、未知代次——各有独立错误类型
- **原子化轮换**：新代次通过 WAL 提交后原子切换，读取方只见完整代次
- **过渡窗口**：轮换后新旧代次在窗口内均可用，窗口后只允许新代次签发，旧凭证按有效期自然失效
- **崩溃恢复**：WAL 重放恢复状态；已提交代次与未完成轮换可区分，恢复到一致状态
- **吊销与续期**：吊销立即生效；续期不可越过代次生命周期；并发续期与吊销安全
- **RBAC 权限控制**：按角色校验签发、校验、轮换、吊销、续期权限
- **可核验审计**：所有签发、轮换、吊销均留审计记录，重启后仍然有效

## 密钥代次模型

每代主密钥经历以下生命周期：

```
Pending ──提交──> Active ──窗口结束──> Retiring ──过期──> Retired ──> Expired
```

| 状态 | 签发 | 校验 | 说明 |
|------|------|------|------|
| `Pending` | - | - | 已生成但未提交，不对外暴露（未完成轮换） |
| `Active` | ✓ | ✓ | 当前签发密钥 |
| `Retiring` | ✓ | ✓ | 过渡窗口内：新旧代次均可签发 |
| `Retired` | - | ✓ | 窗口结束：只可校验，不可签发 |
| `Expired` | - | - | 代次生命周期结束：不可校验与签发 |

**轮换流程：**

1. **生成**：创建新主密钥（`Pending`），写入 `gen_created` 事件并 fsync
2. **提交**：写入 `gen_activated` 事件并 fsync——此为原子提交点
3. **切换**：更新内存状态——新代次转为 `Active`，旧代次转为 `Retiring`
4. **窗口结束**：后台清理协程将 `Retiring` 代次转为 `Retired`（停止签发）
5. **过期**：后台清理协程将 `Retired` 代次转为 `Expired`（停止校验）

**原子性保证：**

- 任一时刻对外暴露的密钥集合只能是某个已提交的完整代次
- 读取方不会观察到代次之间或字段级别的混合状态
- 轮换通过 WAL 事件顺序保证：`gen_created` → `gen_activated` → 内存切换
- 崩溃恢复时，已提交代次（有 `gen_activated` 事件）直接恢复；未完成轮换（仅有 `gen_created` 事件）自动提交恢复

**过渡窗口：**

- 轮换后，旧代次进入 `Retiring` 状态，在 `TransitionWindow` 内仍可签发
- 窗口结束后，旧代次转为 `Retired`，不可签发但仍可校验
- 旧代次签发的凭证按其有效期自然失效，不被提前作废
- 代次的校验窗口（`ExpiredAt`）= 停止签发时间 + 最大凭证有效期

## 凭证生命周期

```
签发 ──> 生效中 ──> 续期（可选）──> 过期
                │
                └──> 吊销（立即失效）
```

**凭证字段：**

- `ID`：唯一凭证标识（UUID）
- `GenerationID`：签发代次
- `Subject`：凭证主体
- `Role`：角色
- `IssuedAt`：签发时间
- `NotBefore`：生效边界
- `NotAfter`：失效边界（续期可延长）
- `Renewable`：是否可续期
- `Signature`：HMAC-SHA256 签名

**校验流程：**

1. 检查代次是否存在且未过期（`GenExpired`）
2. 验证签名（`Forged`）
3. 检查生效边界（`NotYetValid`）
4. 检查租约状态：吊销（`Revoked`）或过期（`Expired`）

**续期规则：**

- 续期不得越过所在代次的生命周期（`NotAfter` ≤ 代次 `ExpiredAt`）
- 续期不得早于当前失效边界
- 吊销后的凭证不可续期
- 并发续期与吊销通过互斥锁保护，不产生多个有效租约或状态回退

**吊销规则：**

- 吊销后凭证立即失效
- 吊销记录持久化到 WAL，重启后仍然有效
- 重复吊销幂等

## 配置项

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `DataDir` | `./data` | WAL 与审计文件存放目录 |
| `TransitionWindow` | `5m` | 轮换过渡窗口时长 |
| `CredentialTTL` | `1h` | 凭证默认有效期 |
| `MaxCredentialTTL` | `24h` | 凭证最大有效期（续期上限） |
| `RotationInterval` | `0` | 自动轮换间隔（0 = 不自动轮换） |
| `SweepInterval` | `1m` | 后台清理过期代次的间隔 |

## 角色与权限

| 操作 | Admin | Issuer | Verifier | Revoker |
|------|-------|--------|----------|---------|
| 签发 | ✓ | ✓ | - | - |
| 校验 | ✓ | ✓ | ✓ | - |
| 轮换 | ✓ | - | - | - |
| 吊销 | ✓ | - | - | ✓ |
| 续期 | ✓ | ✓ | - | - |

越权请求返回 `AuthError` 并记录审计（可追溯）。

## 持久化与恢复

**WAL（预写日志）：**

- 所有变更以事件形式追加到 `wal.log`
- 每次写入后 fsync，保证持久化
- 事件类型：`gen_created`、`gen_activated`、`gen_retired`、`gen_expired`、`cred_issued`、`cred_revoked`、`cred_renewed`、`audit`

**恢复流程：**

1. 重放 WAL 事件重建内存状态
2. 检测未完成轮换（仅有 `gen_created` 无 `gen_activated`），自动提交恢复
3. 检测无活跃代次时创建初始代次
4. 启动后台清理协程

**数据安全注意：**

- WAL 文件包含主密钥，文件权限设为 `0600`
- 生产环境应将 `DataDir` 放在加密存储卷上
- 建议定期备份 WAL 文件

## 快速开始

```bash
# 构建
go build ./...

# 运行演示
go run .

# 运行测试
go test ./... -v

# 运行测试（含数据竞争检测）
go test ./... -race
```

## API 概览

```go
// 创建服务
store, _ := NewStore(config)
store.Start()
defer store.Stop()

// 签发凭证
actor := Actor{ID: "admin", Role: RoleAdmin}
cred, _ := store.Issue(ctx, actor, "service-name", RoleIssuer, time.Hour)

// 校验凭证
err := store.Verify(ctx, cred) // 返回 *VerifyError，Reason 可区分

// 轮换主密钥
newGen, _ := store.Rotate(ctx, actor)

// 吊销凭证
store.Revoke(ctx, actor, cred.ID)

// 续期租约
newNotAfter := time.Now().Add(2 * time.Hour)
lease, _ := store.Renew(ctx, actor, cred.ID, newNotAfter)

// 查看审计
records, _ := store.GetAuditLog(ctx)
```

## 错误类型

| 错误类型 | 失败原因 | 说明 |
|----------|----------|------|
| `VerifyError` | `VerifyExpired` | 凭证已过期 |
| `VerifyError` | `VerifyNotYetValid` | 凭证未生效 |
| `VerifyError` | `VerifyForged` | 签名不匹配或租约不存在 |
| `VerifyError` | `VerifyRevoked` | 凭证已吊销 |
| `VerifyError` | `VerifyGenerationExpired` | 代次已过期 |
| `VerifyError` | `VerifyUnknownGeneration` | 未知代次 |
| `AuthError` | - | 越权操作 |
| `RotationError` | - | 轮换失败（含阶段信息） |
| `LeaseError` | - | 租约操作失败 |
