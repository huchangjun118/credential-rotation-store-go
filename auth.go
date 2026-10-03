package creds

// Permission is an operation that may be granted to a role.
type Permission string

const (
	PermIssue  Permission = "issue"
	PermRevoke Permission = "revoke"
	PermRotate Permission = "rotate"
	PermVerify Permission = "verify"
	PermRenew  Permission = "renew"
)

// Actor is an authenticated caller with roles.
type Actor struct {
	Name  string
	Roles []string
}

// Authorizer maps roles to permissions.
type Authorizer struct {
	grants map[string]map[Permission]bool
}

func NewAuthorizer() *Authorizer {
	return &Authorizer{grants: make(map[string]map[Permission]bool)}
}

// Grant gives a role a permission.
func (z *Authorizer) Grant(role string, p Permission) {
	m, ok := z.grants[role]
	if !ok {
		m = make(map[Permission]bool)
		z.grants[role] = m
	}
	m[p] = true
}

// Allowed reports whether the actor holds the permission via any role.
func (z *Authorizer) Allowed(a Actor, p Permission) bool {
	for _, r := range a.Roles {
		if z.grants[r][p] {
			return true
		}
	}
	return false
}
