package ldapwrappers

import (
	"iatp/thirdparty/sleuth/relationship"
	"iatp/tools"
	"iatp/tools/sddl"

	"github.com/go-ldap/ldap/v3"
)

type User struct {
	HighValue               bool
	Name                    string
	Domain                  string
	ObjectID                string
	DistinguishedName       string
	Description             string
	DontReqPreauth          bool
	PasswordNotReqd         bool
	UnConstrainedDelegation bool
	Sensitive               bool
	Enabled                 bool
	PwdNeverexpires         bool
	LastLogon               uint32
	LastLogonTimestamp      uint32
	PwdLastset              uint32
	ServicePrincipalNames   []string
	HasSpn                  bool
	DisplayName             string
	Email                   string
	Title                   string
	HomeDirectory           string
	UserPassword            string
	AdminCount              bool
	SidHistory              []string

	AllowedToDelegate []string
	SPNTargets        []relationship.SPNTarget
	PrimaryGroupSid   string
	HasSIDHistory     []relationship.GenericMember

	SearchResult *ldap.Entry
}

func (u *User) RichObject(entry *ldap.Entry, domainName string) {
	u.Name = entry.GetAttributeValue("sAMAccountName")
	u.Domain = domainName
	u.ObjectID = sddl.NewSID().ReadBytes(entry.GetRawAttributeValue("objectGUID")).String()
	u.DistinguishedName = entry.GetAttributeValue("objectCategory")
	u.Description = entry.GetAttributeValue("description")

	userAccountControl := tools.BytesToInt(entry.GetRawAttributeValue("useraccountcontrol"))
	u.DontReqPreauth = userAccountControl&DontReqPreauth != 0
	u.PasswordNotReqd = userAccountControl&PasswordNotRequired != 0
	u.UnConstrainedDelegation = userAccountControl&TrustedForDelegation != 0
	u.Sensitive = userAccountControl&NotDelegated != 0
	u.Enabled = userAccountControl&AccountDisable == 0
	u.PwdNeverexpires = userAccountControl&DontExpirePassword != 0

	u.LastLogon = uint32(tools.BytesToInt(entry.GetRawAttributeValue("lastLogon")))
	u.LastLogonTimestamp = uint32(tools.BytesToInt(entry.GetRawAttributeValue("lastLogonTimestamp")))
	u.PwdLastset = uint32(tools.BytesToInt(entry.GetRawAttributeValue("pwdLastSet")))
	u.ServicePrincipalNames = entry.GetAttributeValues("serviceprincipalname")
	u.HasSpn = len(u.ServicePrincipalNames) > 0
	u.DisplayName = entry.GetAttributeValue("displayName")
	u.Email = entry.GetAttributeValue("mail")
	u.Title = entry.GetAttributeValue("title")
	u.HomeDirectory = entry.GetAttributeValue("homeDirectory")
	u.UserPassword = entry.GetAttributeValue("userPassword")

	adminCount := entry.GetRawAttributeValue("adminCount")
	if adminCount != nil {
		u.AdminCount = tools.BytesToInt(adminCount) == 1
	} else {
		u.AdminCount = false
	}

	u.SearchResult = entry
}
