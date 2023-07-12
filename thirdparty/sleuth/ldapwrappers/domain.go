package ldapwrappers

import "iatp/thirdparty/sleuth/relationship"

type Domain struct {
	User               []string
	Computers          []string
	ChildOus           []string
	RemoteDesktopUsers []relationship.GenericMember
	LocalAdmins        []relationship.GenericMember
	DcomUsers          []relationship.GenericMember
	PSRemoteUsers      []relationship.GenericMember
	Links              []relationship.GPLink
}
