package relationship

type ACL struct {
	PrincipalSID  string
	PrincipalType string
	AceType       string
	IsInherited   bool
}
