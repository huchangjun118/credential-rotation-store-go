package main

import "fmt"

// VerifyFailureReason 表示凭证校验失败的具体原因，各原因可区分。
type VerifyFailureReason int

const (
	VerifyOK VerifyFailureReason = iota
	VerifyExpired
	VerifyNotYetValid
	VerifyForged
	VerifyRevoked
	VerifyGenerationExpired
	VerifyUnknownGeneration
)

func (r VerifyFailureReason) String() string {
	switch r {
	case VerifyOK:
		return "ok"
	case VerifyExpired:
		return "expired"
	case VerifyNotYetValid:
		return "not_yet_valid"
	case VerifyForged:
		return "forged"
	case VerifyRevoked:
		return "revoked"
	case VerifyGenerationExpired:
		return "generation_expired"
	case VerifyUnknownGeneration:
		return "unknown_generation"
	default:
		return "unknown"
	}
}

// VerifyError 是凭证校验失败的错误，携带可区分的失败原因。
type VerifyError struct {
	Reason VerifyFailureReason
	Detail string
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("credential verification failed: %s: %s", e.Reason, e.Detail)
}

func (e *VerifyError) Is(target error) bool {
	t, ok := target.(*VerifyError)
	if !ok {
		return false
	}
	return e.Reason == t.Reason
}

// AuthError 表示越权操作被拒绝。
type AuthError struct {
	Actor  string
	Role   Role
	Action string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("authorization denied: actor=%s role=%s action=%s", e.Actor, e.Role, e.Action)
}

// RotationError 表示轮换过程中的错误，携带阶段信息。
type RotationError struct {
	Phase string
	Err   error
}

func (e *RotationError) Error() string {
	return fmt.Sprintf("rotation failed at phase %s: %v", e.Phase, e.Err)
}

func (e *RotationError) Unwrap() error {
	return e.Err
}

// LeaseError 表示租约操作（续期/吊销）失败。
type LeaseError struct {
	CredentialID string
	Operation    string
	Err          error
}

func (e *LeaseError) Error() string {
	return fmt.Sprintf("lease %s failed for credential %s: %v", e.Operation, e.CredentialID, e.Err)
}

func (e *LeaseError) Unwrap() error {
	return e.Err
}
