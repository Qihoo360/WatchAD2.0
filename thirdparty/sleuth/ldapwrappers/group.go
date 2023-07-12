package ldapwrappers

import "iatp/thirdparty/sleuth/relationship"

type Group struct {
	Members []relationship.GenericMember
}
