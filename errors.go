package creds

import "errors"

// FailureReason distinguishes why a credential verification failed so that
// expired, forged and revoked credentials are never conflated.
type FailureReason string

const (
	ReasonExpired          FailureReason = "expired"
	ReasonNotYetValid      FailureReason = "not_yet_valid"
	ReasonForged           FailureReason = "forged"
	ReasonRevoked          FailureReason = "revoked"
	ReasonUnknownKeyGen    FailureReason = "unknown_key_generation"
	ReasonMalformed        FailureReason = "malformed"
	ReasonPermissionDenied FailureReason = "permission_denied"
	ReasonLeaseConflict    FailureReason = "lease_conflict"
	ReasonRotationConflict FailureReason = "rotation_conflict"
)

// VerifyError is a typed failure with a machine-distinguishable reason.
type VerifyError struct {
	Reason FailureReason
	Detail string
}

func (e *VerifyError) Error() string {
	if e.Detail == "" {
		return string(e.Reason)
	}
	return string(e.Reason) + ": " + e.Detail
}

func newErr(r FailureReason, detail string) *VerifyError {
	return &VerifyError{Reason: r, Detail: detail}
}

// ReasonOf extracts the FailureReason from an error, if any.
func ReasonOf(err error) (FailureReason, bool) {
	var ve *VerifyError
	if errors.As(err, &ve) {
		return ve.Reason, true
	}
	return "", false
}
