package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"time"
)

// Credential 是基于主密钥派生签发的短时凭证。
type Credential struct {
	ID           string
	GenerationID int64
	Subject      string
	Role         Role
	IssuedAt     time.Time
	NotBefore    time.Time
	NotAfter     time.Time
	Renewable    bool
	Signature    []byte
}

// credentialPayload 是参与签名的确定性载荷（不含 Signature）。
type credentialPayload struct {
	ID           string `json:"id"`
	GenerationID int64  `json:"generation_id"`
	Subject      string `json:"subject"`
	Role         string `json:"role"`
	IssuedAt     int64  `json:"issued_at"`
	NotBefore    int64  `json:"not_before"`
	NotAfter     int64  `json:"not_after"`
	Renewable    bool   `json:"renewable"`
}

// deriveSigningKey 从主密钥派生签发密钥（HKDF-like：HMAC-SHA256 派生）。
func deriveSigningKey(masterKey []byte, genID int64) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("credential-signing-key"))
	mac.Write([]byte{byte(genID), byte(genID >> 8), byte(genID >> 16), byte(genID >> 24)})
	return mac.Sum(nil)
}

// payloadBytes 返回参与签名的确定性字节。
func (c *Credential) payloadBytes() ([]byte, error) {
	p := credentialPayload{
		ID:           c.ID,
		GenerationID: c.GenerationID,
		Subject:      c.Subject,
		Role:         string(c.Role),
		IssuedAt:     c.IssuedAt.UnixNano(),
		NotBefore:    c.NotBefore.UnixNano(),
		NotAfter:     c.NotAfter.UnixNano(),
		Renewable:    c.Renewable,
	}
	return json.Marshal(p)
}

// sign 使用指定代次的主密钥对凭证签名，填充 Signature 字段。
func (c *Credential) sign(masterKey []byte) error {
	key := deriveSigningKey(masterKey, c.GenerationID)
	data, err := c.payloadBytes()
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	c.Signature = mac.Sum(nil)
	return nil
}

// verifySignature 校验凭证签名是否与代次主密钥匹配（防伪造）。
func (c *Credential) verifySignature(masterKey []byte) bool {
	key := deriveSigningKey(masterKey, c.GenerationID)
	data, err := c.payloadBytes()
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, c.Signature)
}

// checkTimeBounds 校验凭证自身的生效/失效边界。
func (c *Credential) checkTimeBounds(now time.Time) VerifyFailureReason {
	if now.Before(c.NotBefore) {
		return VerifyNotYetValid
	}
	if now.After(c.NotAfter) {
		return VerifyExpired
	}
	return VerifyOK
}
