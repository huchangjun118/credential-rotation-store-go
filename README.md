# credential-rotation-store-go

本地进程内的密钥轮换与短时凭证发放服务。服务按需向下游签发带有效期的
凭证，底层主密钥定期轮换；签发、校验、吊销、续期与轮换全部在本地完成，
不依赖任何外部服务。

## 密钥代次模型

密钥以**代次（Generation）**组织，每一代是一个独立的主密钥：

| 状态 | 可签发 | 可校验 | 说明 |
|------|--------|--------|------|
| `active`   | ✔ | ✔ | 当前代次，唯一无签发时限的代次 |
| `retiring` | 窗口内 ✔ | ✔ | 轮换后的旧代次，`SignUntil` 前处于过渡窗口 |
| `retired`  | ✘ | ✔ | 窗口结束后的旧代次，仅校验，已签发凭证按自身有效期自然失效 |

- 对外暴露的密钥集合永远是**某个已提交的完整代次快照**（`KeyRing`）。
  轮换先写 WAL 的 `rotate_begin`，再写包含完整新快照的 `gen_commit`，
  随后通过 `atomic.Pointer` 一次性发布；读取方绝不会观察到代次之间或
  字段级别的混合状态。
- 轮换中途崩溃：WAL 中只有 `rotate_begin` 而没有 `gen_commit`，恢复时
  该记录被丢弃，系统回到上一个已提交代次，新旧状态始终可区分。
- 所有已提交代次永久保留在快照中，因此旧代次签发的凭证在其有效期内
  始终可校验，不会被轮换提前作废。

## 凭证生命周期

```
Issue ──► active ──Renew──► active(延长) ──► expired
              │
              └──Revoke──► revoked（立即生效，终态）
```

- 凭证为 `base64url(claims).base64url(HMAC-SHA256)` 格式，claims 携带
  `nbf`/`exp` 明确的生效与失效边界及所属代次 `gen`。
- **校验失败原因可区分**（`ReasonOf`）：`forged`（签名不符）、
  `expired`（超过失效边界）、`revoked`（已吊销）、`not_yet_valid`、
  `malformed`、`unknown_key_generation`。判定顺序确定：先签名，再吊销，
  再时间边界，互不混淆。
- **吊销立即生效**且为终态：吊销记录先落 WAL（fsync）再更新内存状态，
  重启后仍然有效；吊销后的续期一律被拒绝，不会状态回退。
- **续期**受三重约束，且不会越过所在代次的生命周期：
  1. 单次延长不超过 `RenewalMax`；
  2. 新失效时间不超过"当前时刻 + `CredentialTTL`"；
  3. 对非 active 代次，不超过 `SignUntil + CredentialTTL`（代次生命周期终点）。
- 同一凭证的并发续期与吊销由同一把互斥锁串行化：要么续期先生效、要么
  吊销先生效，绝不会产生多个有效租约或吊销被续期覆盖。
- 签发、轮换、吊销、续期与越权拒绝都会写入**哈希链审计日志**，并镜像到
  WAL，重启后链完整性仍可校验（`VerifyAuditChain`）。

## 角色与权限

通过 `Authorizer` 按角色授权，越权请求被拒绝并留下 `denied` 审计：

| 权限 | 操作 |
|------|------|
| `PermIssue`  | `Issue`  |
| `PermRevoke` | `Revoke` |
| `PermRotate` | `Rotate` |
| `PermRenew`  | `Renew`  |

## 配置项（`Config`）

| 字段 | 默认 | 说明 |
|------|------|------|
| `JournalPath`      | `""`（纯内存） | WAL 文件路径；非空时所有提交记录 fsync 落盘 |
| `CredentialTTL`    | 1h   | 凭证默认有效期 |
| `TransitionWindow` | 1m   | 轮换后旧代次仍可签发的过渡窗口 |
| `RenewalMax`       | = TTL | 单次续期最大延长量 |

## 持久化与恢复

WAL 为追加式 JSON 行日志，记录类型：`rotate_begin`、`gen_commit`、
`issue`、`renew`、`revoke`、`audit`。恢复时按序回放：

- `gen_commit` 直接恢复完整密钥环快照；
- `issue`/`renew`/`revoke` 重建租约表，签发序号从最大已用序号续接，
  不会重复签发或漏记；
- 末尾的撕裂写（崩溃残留）被安全忽略；
- 无匹配 `gen_commit` 的 `rotate_begin` 被丢弃。

## 测试

```sh
go test -race ./...
```

覆盖：并发签发与轮换、轮换原子可见性、过渡窗口边界、吊销/续期竞争、
重启恢复（含未完成轮换与撕裂日志）、失败原因区分与越权审计。

## 使用示例

```go
clk := creds.NewManualClock(time.Now()) // 生产环境传 nil 使用真实时钟
authz := creds.NewAuthorizer()
authz.Grant("issuer", creds.PermIssue)

svc, _ := creds.New(creds.Config{
    JournalPath:      "/var/lib/creds/wal.log",
    CredentialTTL:    5 * time.Minute,
    TransitionWindow: time.Minute,
}, nil, authz)
defer svc.Close()

tok, claims, _ := svc.Issue(creds.Actor{Name: "api", Roles: []string{"issuer"}}, "svc-a", nil)
_ = claims
got, err := svc.Verify(creds.Actor{}, tok)
if err != nil {
    reason, _ := creds.ReasonOf(err) // expired / forged / revoked / ...
    _ = reason
}
_ = got
```
