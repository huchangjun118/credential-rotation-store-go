package main

import "time"

// Config 是服务配置。
type Config struct {
	// DataDir 是 WAL 与审计文件的存放目录。
	DataDir string
	// TransitionWindow 是轮换过渡窗口时长：窗口内旧代次仍可签发，窗口后只允许新代次签发。
	TransitionWindow time.Duration
	// CredentialTTL 是凭证默认有效期。
	CredentialTTL time.Duration
	// MaxCredentialTTL 是凭证最大有效期（续期不可超过此时长）。
	MaxCredentialTTL time.Duration
	// RotationInterval 是自动轮换间隔，0 表示不自动轮换。
	RotationInterval time.Duration
	// SweepInterval 是后台清理过期代次的间隔。
	SweepInterval time.Duration
}

// DefaultConfig 返回默认配置。
func DefaultConfig() Config {
	return Config{
		DataDir:          "./data",
		TransitionWindow: 5 * time.Minute,
		CredentialTTL:    1 * time.Hour,
		MaxCredentialTTL: 24 * time.Hour,
		RotationInterval: 0,
		SweepInterval:    1 * time.Minute,
	}
}
