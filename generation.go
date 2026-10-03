package main

import "time"

// GenerationStatus 是密钥代次状态。
type GenerationStatus int

const (
	// GenPending 已生成但未提交，不对外暴露。
	GenPending GenerationStatus = iota
	// GenActive 已提交，当前签发密钥。
	GenActive
	// GenRetiring 过渡窗口内：仍可签发与校验，窗口后转为 Retired。
	GenRetiring
	// GenRetired 只可校验，不可签发。
	GenRetired
	// GenExpired 不可校验与签发。
	GenExpired
)

func (s GenerationStatus) String() string {
	switch s {
	case GenPending:
		return "pending"
	case GenActive:
		return "active"
	case GenRetiring:
		return "retiring"
	case GenRetired:
		return "retired"
	case GenExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// KeyGeneration 是一代主密钥及其生命周期元数据。
type KeyGeneration struct {
	ID          int64
	Key         []byte
	Status      GenerationStatus
	CreatedAt   time.Time
	ActivatedAt time.Time
	RetiredAt   time.Time // 从 Retiring 转为 Retired 的时间（停止签发）
	ExpiredAt   time.Time // 从 Retired 转为 Expired 的时间（停止校验）
}

// canSign 判断该代次是否可用于签发。
func (g *KeyGeneration) canSign(now time.Time) bool {
	switch g.Status {
	case GenActive:
		return true
	case GenRetiring:
		return now.Before(g.RetiredAt)
	default:
		return false
	}
}

// canVerify 判断该代次是否可用于校验。
func (g *KeyGeneration) canVerify(now time.Time) bool {
	switch g.Status {
	case GenActive, GenRetiring, GenRetired:
		// ExpiredAt 为零值表示当前活跃代次尚未设定过期时间，仍可校验
		if g.ExpiredAt.IsZero() {
			return true
		}
		return now.Before(g.ExpiredAt)
	default:
		return false
	}
}
