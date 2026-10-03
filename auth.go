package main

// Role 是操作角色。
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleIssuer   Role = "issuer"
	RoleVerifier Role = "verifier"
	RoleRevoker  Role = "revoker"
)

// Actor 是操作发起者，携带身份与角色。
type Actor struct {
	ID   string
	Role Role
}

// Action 是操作类型。
type Action string

const (
	ActionIssue   Action = "issue"
	ActionVerify  Action = "verify"
	ActionRotate  Action = "rotate"
	ActionRevoke  Action = "revoke"
	ActionRenew   Action = "renew"
)

// allowedRoles 定义各操作允许的角色。
var allowedRoles = map[Action]map[Role]bool{
	ActionIssue:  {RoleAdmin: true, RoleIssuer: true},
	ActionVerify: {RoleAdmin: true, RoleIssuer: true, RoleVerifier: true},
	ActionRotate: {RoleAdmin: true},
	ActionRevoke: {RoleAdmin: true, RoleRevoker: true},
	ActionRenew:  {RoleAdmin: true, RoleIssuer: true},
}

// canPerform 判断角色是否可执行某操作。
func canPerform(role Role, action Action) bool {
	roles, ok := allowedRoles[action]
	if !ok {
		return false
	}
	return roles[role]
}
