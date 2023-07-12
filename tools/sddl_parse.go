package tools

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

/*
SDDL 语法解析器
*/

var SIDString = map[string]string{
	"AN": "Anonymous Logon",
	"AO": "Account Operators",
	"AU": "Authenticated Users",
	"BA": "Built-in Administrators",
	"BG": "Built-in Guests",
	"BO": "Backup Operators",
	"BU": "Built-in Users",
	"CA": "Certificate Publishers",
	"CD": "Certificate DCOM User",
	"CG": "Creator Group",
	"CO": "Creator Owner",
	"DA": "Domain Administrators",
	"DC": "Domain Computers",
	"DD": "Domain Controllers",
	"DG": "Domain Guests",
	"DU": "Domain Users",
	"EA": "Enterprise Administrators",
	"ED": "Enterprise Domain Controllers",
	"HI": "High Integrity level",
	"IU": "Interactively Logged-on User",
	"LA": "Local Administrator",
	"LG": "Local Guest",
	"LS": "Local Service Account",
	"LW": "Low Integrity Level",
	"ME": "Medium Integrity Level",
	"MU": "Performance Monitor Users",
	"NO": "Network Configuration Operators",
	"NS": "Network Service Account",
	"NU": "Network Logon User",
	"PA": "Group Policy Administrators",
	"PO": "Printer Operators",
	"PS": "Principal Self",
	"PU": "Power Users",
	"RC": "Restricted Code",
	"RD": "Terminal Server Users",
	"RE": "Replicator",
	"RO": "Enterprise Read-only Domain Controllers",
	"RS": "RAS Servers Group",
	"RU": "PREW2KCOMPACCESS",
	"SA": "Schema Administrators",
	"SI": "System Integrity Level",
	"SO": "Server operators",
	"SU": "Service Logon User",
	"SY": "Local System",
	"WD": "Everyone",
}

var ACLFlags = map[string]string{
	"P":                 "The SE_DACL_PROTECTED flag is set",
	"AR":                "The SE_DACL_AUTO_INHERIT_REQ flag is set",
	"AI":                "The SE_DACL_AUTO_INHERITED flag is set",
	"NO_ACCESS_CONTROL": "The ACL is null",

	"SR": "Self Relative",
	"RM": "RM Control Valid",
	"PS": "SACL Protected",
	"PD": "DACL Protected",
	"SI": "SACL Auto-Inherited",
	"DI": "DACL Auto-Inherited",
	"SC": "SACL Computed Inheritance Required",
	"DC": "DACL Computed Inheritance Required",
	"SS": "Server Security",
	"DT": "DACL Trusted",
	"SD": "SACL Defaulted",
	"SP": "SACL Present",
	"DD": "DACL Defaulted",
	"DP": "DACL Present",
	"GD": "Group Defaulted",
	"OD": "Owner Defaulted",
}

var ACETypes = map[string]string{
	"A":  "Access Allowed",
	"D":  "Access Denied",
	"AU": "Audit",
	"OA": "Object Access Allowed",
	"OD": "Object Access Denied",
	"OU": "Object Audit",
	"ML": "Mandatory Label",
	"SP": "Central Policy ID",
}

var ConditionalAceTypes = map[string]string{
	"XA": "Access Allowed Callback",
	"XD": "Access Denied Callback",
	"XU": "Access Allowed Object Callback",
	"ZA": "Audit Callback",
}

var ACEFlags = map[string]string{
	"CI": "Child objects that are containers, such as directories, inherit the ACE as an effective ACE. The inherited ACE is inheritable unless the NO_PROPAGATE_INHERIT_ACE bit flag is also set.",
	"OI": "Noncontainer child objects inherit the ACE as an effective ACE.\nFor child objects that are containers, the ACE is inherited as an inherit-only ACE unless the NO_PROPAGATE_INHERIT_ACE bit flag is also set.",
	"NP": "If the ACE is inherited by a child object, the system clears the OBJECT_INHERIT_ACE and CONTAINER_INHERIT_ACE flags in the inherited ACE. This prevents the ACE from being inherited by subsequent generations of objects.",
	"IO": "Indicates an inherit-only ACE, which does not control access to the object to which it is attached. If this flag is not set, the ACE is an effective ACE which controls access to the object to which it is attached.\nBoth effective and inherit-only ACEs can be inherited depending on the state of the other inheritance flags.",
	"ID": "Indicates that the ACE was inherited. The system sets this bit when it propagates an inherited ACE to a child object.",
	"SA": "Used with system-audit ACEs in a SACL to generate audit messages for successful access attempts.",
	"FA": "Used with system-audit ACEs in a system access control list (SACL) to generate audit messages for failed access attempts.",
}

var Rights = map[string]string{
	"GR": "Generic Read",
	"GW": "Generic Write",
	"GX": "Generic Execute",
	"GA": "Generic All",
	"WO": "Write Owner",
	"WD": "Write DAC",
	"RC": "Read Control",
	"SD": "Delete",
	"FA": "File All Access",
	"FX": "File Execute",
	"FW": "File Write",
	"FR": "File Read",
	"KA": "Key All Access",
	"KR": "Key Read",
	"KX": "Key Execute",
	"KW": "Key Write",
	"CR": "Control Access",
	"LO": "List Object",
	"DT": "Delete Tree",
	"WP": "Write Property",
	"RP": "Read Property",
	"SW": "Self Write",
	"LC": "List Children",
	"DC": "Delete Child",
	"CC": "Create Child",
}

var Guid = map[string]string{
	"ee914b82-0a98-11d1-adbb-00c04fd8d5cd": "Abandon-Replication",
	"440820ad-65b4-11d1-a3da-0000f875ae0d": "Add-GUID",
	"1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd": "Allocate-Rids",
	"68b1d179-0d15-4d4f-ab71-46152e79a7bc": "Allowed-To-Authenticate",
	"edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply-Group-Policy",
	"0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
	"a05b8cc2-17bc-4802-a710-e7c15ab866a2": "Certificate-AutoEnrollment",
	"014bf69c-7b3b-11d1-85f6-08002be74fab": "Change-Domain-Master",
	"cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "Change-Infrastructure-Master",
	"bae50096-4752-11d1-9052-00c04fc2d4cf": "Change-PDC",
	"d58d5f36-0a98-11d1-adbb-00c04fd8d5cd": "Change-Rid-Master",
	"e12b56b6-0a95-11d1-adbb-00c04fd8d5cd": "Change-Schema-Master",
	"e2a36dc9-ae17-47c3-b58b-be34c55ba633": "Create-Inbound-Forest-Trust",
	"fec364e0-0a98-11d1-adbb-00c04fd8d5cd": "Do-Garbage-Collection",
	"ab721a52-1e2f-11d0-9819-00aa0040529b": "Domain-Administer-Server",
	"69ae6200-7f46-11d2-b9ad-00c04f79f805": "DS-Check-Stale-Phantoms",
	"2f16c4a5-b98e-432c-952a-cb388ba33f2e": "DS-Execute-Intentions-Script",
	"9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
	"4ecc03fe-ffc0-4947-b630-eb672a8a9dbc": "DS-Query-Self-Quota",
	"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
	"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
	"89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
	"1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
	"f98340fb-7c5b-4cdb-a00b-2ebdfa115a96": "DS-Replication-Monitor-Topology",
	"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
	"05c74c5e-4deb-43b4-bd9f-86664c2a7fd5": "Enable-Per-User-Reversibly-Encrypted-Password",
	"b7b1b3de-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Logging",
	"b7b1b3dd-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Planning",
	"7c0e2a7c-a419-48e4-a995-10180aad54dd": "Manage-Optional-Features",
	"ba33815a-4f93-4c76-87f3-57574bff8109": "Migrate-SID-History",
	"b4e60130-df3f-11d1-9c86-006008764d0e": "msmq-Open-Connector",
	"06bd3201-df3e-11d1-9c86-006008764d0e": "msmq-Peek",
	"4b6e08c3-df3c-11d1-9c86-006008764d0e": "msmq-Peek-computer-Journal",
	"4b6e08c1-df3c-11d1-9c86-006008764d0e": "msmq-Peek-Dead-Letter",
	"06bd3200-df3e-11d1-9c86-006008764d0e": "msmq-Receive",
	"4b6e08c2-df3c-11d1-9c86-006008764d0e": "msmq-Receive-computer-Journal",
	"4b6e08c0-df3c-11d1-9c86-006008764d0e": "msmq-Receive-Dead-Letter",
	"06bd3203-df3e-11d1-9c86-006008764d0e": "msmq-Receive-journal",
	"06bd3202-df3e-11d1-9c86-006008764d0e": "msmq-Send",
	"a1990816-4298-11d1-ade2-00c04fd8d5cd": "Open-Address-Book",
	"1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": "Read-Only-Replication-Secret-Synchronization",
	"45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
	"0bc1554e-0a99-11d1-adbb-00c04fd8d5cd": "Recalculate-Hierarchy",
	"62dd28a8-7f46-11d2-b9ad-00c04f79f805": "Recalculate-Security-Inheritance",
	"ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",
	"9432c620-033c-4db7-8b58-14ef6d0bf477": "Refresh-Group-Cache",
	"1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8": "Reload-SSL-Certificate",
	"7726b9d5-a4b4-4288-a6b2-dce952e80a7f": "Run-Protect_Admin_Groups-Task",
	"91d67418-0135-4acc-8d79-c08e857cfbec": "SAM-Enumerate-Entire-Domain",
	"ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
	"ab721a55-1e2f-11d0-9819-00aa0040529b": "Send-To",
	"ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "Unexpire-Password",
	"280f369c-67c7-438e-ae98-1d46f3c6f541": "Update-Password-Not-Required-Bit",
	"be2bb760-7f46-11d2-b9ad-00c04f79f805": "Update-Schema-Cache",
	"ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
	"00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
	"91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private-Information",
	"72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS-Host-Name-Attributes",
	"b8119fd0-04f6-4762-ab7a-4986c76b3f9a": "Domain-Other-Parameters",
	"c7407360-20bf-11d0-a768-00aa006e0529": "Domain-Password",
	"e45795b2-9455-11d1-aebd-0000f80367c1": "Email-Information",
	"59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General-Information",
	"bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership",
	"ffa6f046-ca4b-4feb-b40d-04dfee722543": "MS-TS-GatewayAccess",
	"77b5b886-944a-11d1-aebd-0000f80367c1": "Personal-Information",
	"e48d0154-bcf8-11d1-8702-00c04fb96050": "Public-Information",
	"037088f8-0ae1-11d2-b422-00a0c968f939": "RAS-Information",
	"5805bc62-bdc9-4428-a5e2-856a0f4c185e": "Terminal-Server-License-Server",
	"4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
	"5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon",
	"e45795b3-9455-11d1-aebd-0000f80367c1": "Web-Information",
}

type ParseEngine interface {
	Parse(sddlStr string) error
}

type SddlEngine struct {
	Owner string `json:"owner"`
	Group string `json:"group"`
	Dacl  Acl    `json:"dacl"`
	Sacl  Acl    `json:"sacl"`
}

type Acl struct {
	AclFlagString string   `json:"acl_flag_string"`
	AclFlagDesc   []string `json:"acl_flag_desc"`
	Aces          []Ace    `json:"aces_list"`
}

type Ace struct {
	AceType           string   `json:"ace_type"`
	AceFlagString     string   `json:"ace_flag_string"`
	AceFlagDesc       []string `json:"ace_flag_desc"`
	AceRights         []string `json:"ace_rights"`
	ObjectGuid        string   `json:"object_guid"`
	InheritObjectGuid string   `json:"inherit_object_guid"`
	SidString         string   `json:"sid_string"`
}

type SddlError struct {
	SddlExpression string
	err            error
}

type AclError struct {
	SddlError
	AclExpression string
}

type AceError struct {
	SddlError
	AceExpression string
}

func (se *SddlError) Error() string {
	return fmt.Sprintf("SDDL error: %v\noriginal expression: %s", se.err, se.SddlExpression)
}

func (ae *AclError) Error() string {
	return fmt.Sprintf("Acl error: %v\noriginal sddl expression: %s \noriginal acl expression: %s \n",
		ae.err, ae.SddlExpression, ae.AclExpression)
}

func (acerr *AceError) Error() string {
	return fmt.Sprintf("Ace error: %v\noriginal sddl expression: %s \noriginal ace expression: %s \n",
		acerr.err, acerr.SddlExpression, acerr.AceExpression)
}

func ErrorWarp(function func(s string) (Acl, error), aclStr string, sddl string) (Acl, error) {
	value, err := function(aclStr)
	if err != nil {
		switch err.(type) {
		case *AclError:
			err.(*AclError).SddlExpression = sddl
		case *AceError:
			err.(*AceError).SddlExpression = sddl
		}
		return Acl{}, err
	} else {
		return value, nil
	}
}

var (
	SddlRegexp *regexp.Regexp
	AclRegexp  *regexp.Regexp
)

func init() {
	SddlRegexp = regexp.MustCompile(`O:(.*)G:(.*)D:(.*)S:(.*)`)
	AclRegexp = regexp.MustCompile(`([A-Z]{1,})(.*)`)
}

func (se *SddlEngine) Parse(sddlStr string) error {
	params := SddlRegexp.FindStringSubmatch(sddlStr)[1:]

	if len(params) != 4 {
		err := SddlError{}
		err.err = errors.New("The SDDL expression is ill-formatted")
		err.SddlExpression = sddlStr
		return &err
	}

	se.Owner = se.parseSidStr(params[0])
	se.Group = se.parseSidStr(params[1])
	if acl, err := ErrorWarp(se.parseAcl, params[2], sddlStr); err != nil {
		return err
	} else {
		se.Dacl = acl
	}
	if acl, err := ErrorWarp(se.parseAcl, params[2], sddlStr); err != nil {
		return err
	} else {
		se.Sacl = acl
	}
	return nil
}

func (se *SddlEngine) parseSidStr(sid string) string {
	if value, ok := SIDString[sid]; !ok {
		return sid
	} else {
		return value
	}
}

// ACL 解析器
func (se *SddlEngine) parseAcl(aclStr string) (Acl, error) {
	var acl Acl
	aclFields := AclRegexp.FindStringSubmatch(aclStr)

	if len(aclFields) != 3 {
		err := AclError{}
		err.AclExpression = aclStr
		err.err = errors.New("The ACL expression is ill-formatted")
		return Acl{}, &err
	}

	aclFields = aclFields[1:]
	acl.AclFlagString = aclFields[0]
	acl.AclFlagDesc = se.parseFlags(aclFields[0], ACLFlags)

	aces := regexp.MustCompile(`\((.*?)\)`).FindAllStringSubmatch(aclFields[1], -1)
	for _, v := range aces {
		if ace, err := se.parseAce(v[1]); err != nil {
			return Acl{}, err
		} else {
			acl.Aces = append(acl.Aces, ace)
		}
	}

	return acl, nil
}

// ACE 解析器
func (se *SddlEngine) parseAce(aceStr string) (Ace, error) {
	var ace Ace
	fields := strings.Split(aceStr, ";")
	if len(fields) != 6 {
		err := AceError{}
		err.AceExpression = aceStr
		err.err = errors.New("The Ace expression is ill-formatted")
		return Ace{}, &err
	}

	ace.AceType = ACETypes[fields[0]]
	ace.AceFlagString = fields[1]
	ace.AceFlagDesc = se.parseFlags(fields[1], ACEFlags)
	ace.AceRights = se.parseFlags(fields[2], Rights)
	ace.ObjectGuid = se.parseGuid(fields[3])
	ace.InheritObjectGuid = se.parseGuid(fields[4])
	if value, ok := SIDString[fields[5]]; ok {
		ace.SidString = value
	} else {
		switch {
		case strings.HasSuffix(fields[5], "-498"):
			ace.SidString = "ENTERPRISE_READONLY_DOMAIN_CONTROLLERS"
		case fields[5] == "S-1-5-32-561":
			ace.SidString = "Builtin Terminal Server License Servers"
		case strings.HasSuffix(fields[5], "-519"):
			ace.SidString = "Enterprise Administrators"
		default:
			ace.SidString = fields[5]
		}
	}

	return ace, nil
}

// 解析Guid
func (se *SddlEngine) parseGuid(r string) string {
	if v, ok := Guid[r]; ok {
		return v
	}
	return r
}

// 解析权限
func (se *SddlEngine) parseFlags(r string, flags map[string]string) []string {
	var result []string
	for k, _ := range r {
		if _, ok := flags[r[k:k+1]]; ok {
			if _, ok := flags[r[k:k+2]]; !ok {
				result = append(result, flags[r[k:k+1]])
				continue
			}
		}
		if (k+1)%2 == 0 {
			result = append(result, flags[r[k-1:k+1]])
		}
	}
	return result
}
