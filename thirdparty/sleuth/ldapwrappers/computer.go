package ldapwrappers

import "iatp/thirdparty/sleuth/relationship"

type Computer struct {
	Node

	SamAccountName     string
	AllowedToDelegate  []string
	AllowedToAct       []relationship.GenericMember
	Sessions           []relationship.Session
	PingFailed         bool
	LocalAdmins        []relationship.GenericMember
	RemoteDesktopUsers []relationship.GenericMember
	DcomUsers          []relationship.GenericMember
	PSRemoteUsers      []relationship.GenericMember
	IsStealthTarget    []relationship.GenericMember
	IsDomainController bool
	IsWindows          bool
}
