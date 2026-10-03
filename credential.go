package creds

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// Claims is the signed payload of a credential.
type Claims struct {
	ID         string    `json:"id"`
	Subject    string    `json:"subject"`
	Roles      []string  `json:"roles,omitempty"`
	Generation uint64    `json:"gen"`
	NotBefore  time.Time `json:"nbf"`
	NotAfter   time.Time `json:"exp"`
	Seq        uint64    `json:"seq"`
}

// Valid reports whether the claims are within their time bounds at t.
func (c *Claims) Valid(t time.Time) bool {
	return !t.Before(c.NotBefore) && t.Before(c.NotAfter)
}

// encodeToken serializes claims and signs them with key (HMAC-SHA256).
// Format: base64url(payload).base64url(sig)
func encodeToken(c *Claims, key []byte) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// decodeToken parses a token and verifies its signature with key.
// A signature mismatch yields ReasonForged.
func decodeToken(tok string, key []byte) (*Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return nil, newErr(ReasonMalformed, "token must have two segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, newErr(ReasonMalformed, "payload is not base64url")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, newErr(ReasonMalformed, "signature is not base64url")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, newErr(ReasonForged, "signature mismatch")
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, newErr(ReasonMalformed, "payload is not valid claims")
	}
	return &c, nil
}

// splitTokenGen extracts the generation id without verifying the signature,
// so Verify can select the right key before checking authenticity.
func splitTokenGen(tok string) (uint64, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return 0, newErr(ReasonMalformed, "token must have two segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, newErr(ReasonMalformed, "payload is not base64url")
	}
	var probe struct {
		Generation uint64 `json:"gen"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return 0, newErr(ReasonMalformed, "payload is not valid claims")
	}
	return probe.Generation, nil
}
