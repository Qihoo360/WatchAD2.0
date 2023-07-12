package sddl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	CONTAINER_INHERIT_ACE      = 2
	FAILED_ACCESS_ACE_FLAG     = 128
	INHERIT_ONLY_ACE           = 8
	INHERITED_ACE              = 16
	NO_PROPAGATE_INHERIT_ACE   = 4
	OBJECT_INHERIT_ACE         = 1
	SUCCESSFUL_ACCESS_ACE_FLAG = 64
)

const (
	ACCESS_ALLOWED_ACE_TYPE                 = 0
	ACCESS_DENIED_ACE_TYPE                  = 1
	SYSTEM_AUDIT_ACE_TYPE                   = 2
	SYSTEM_ALARM_ACE_TYPE                   = 3
	ACCESS_ALLOWED_COMPOUND_ACE_TYPE        = 4
	ACCESS_ALLOWED_OBJECT_ACE_TYPE          = 5
	ACCESS_DENIED_OBJECT_ACE_TYPE           = 6
	SYSTEM_AUDIT_OBJECT_ACE_TYPE            = 7
	SYSTEM_ALARM_OBJECT_ACE_TYPE            = 8
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE        = 9
	ACCESS_DENIED_CALLBACK_ACE_TYPE         = 10
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 11
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  = 12
	SYSTEM_AUDIT_CALLBACK_ACE_TYPE          = 13
	SYSTEM_ALARM_CALLBACK_ACE_TYPE          = 14
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   = 15
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   = 16
	SYSTEM_MANDATORY_LABEL_ACE_TYPE         = 17
	SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      = 18
	SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        = 19
)

const (
	GENERIC_READ           = 2147483648
	GENERIC_WRITE          = 67108864
	GENERIC_EXECUTE        = 536870912
	GENERIC_ALL            = 268435456
	MAXIMUM_ALLOWED        = 33554432
	ACCESS_SYSTEM_SECURITY = 16777216
	SYNCHRONIZE            = 1048576
	WRITE_OWNER            = 524288
	WRITE_DACL             = 262144
	READ_CONTROL           = 131072
	DELETE                 = 65536
)

var access_mask = map[uint32]string{
	GENERIC_READ:           "GR",
	GENERIC_WRITE:          "GW",
	GENERIC_EXECUTE:        "GX",
	GENERIC_ALL:            "GA",
	MAXIMUM_ALLOWED:        "MA",
	ACCESS_SYSTEM_SECURITY: "AS",
	SYNCHRONIZE:            "SY",
	WRITE_OWNER:            "WO",
	WRITE_DACL:             "WD",
	READ_CONTROL:           "RC",
	DELETE:                 "DE",
}

var AceTypeMap = map[uint8]string{
	// ace-type
	0:  "A",
	1:  "D",
	2:  "AU",
	5:  "OA",
	6:  "OD",
	7:  "OU",
	17: "ML",
	19: "SP",

	// confitional-ace-type
	9:  "XA",
	10: "XD",
	11: "XU",
	13: "ZA",
}

var AceFlagsMap = map[uint8]string{
	2:   "CI",
	1:   "OI",
	4:   "NP",
	8:   "IO",
	16:  "ID",
	64:  "SA",
	128: "FA",
}

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070
var AceRightsMap = map[uint32]string{
	2147483648: "GR", // Generic Read
	1073741824: "GW", // Generic Write
	536870912:  "GX", // Generic Execute
	268435456:  "GA", // Generic All

	524288: "WO", // Write Owner
	262144: "WD", // Write DAC
	131072: "RC", // Read Control
	65536:  "SD", // Delete

	2032127: "FA", // File All Access
	1179808: "FX", // File Execute
	1179926: "FW", // File Write
	1179785: "FR", // File Read

	983103: "KA", // Key All Access
	131097: "KR", // Key Read
	131078: "KW", // Key Write

	256: "CR", // Control Access
	128: "LO", // List Object
	64:  "DT", // Delete Tree
	32:  "WP", // Write Property
	16:  "RP", // Read Property
	8:   "SW", // Self Write
	4:   "LC", // List Children
	2:   "DC", // Delete Child
	1:   "CC", // Create Child
}

// ACCESS_ALLOWED_OBJECT_ACE MASK
const (
	ADS_RIGHT_DS_CONTROL_ACCESS = 256
	ADS_RIGHT_DS_CREATE_CHILD   = 1
	ADS_RIGHT_DS_DELETE_CHILD   = 2
	ADS_RIGHT_DS_READ_PROP      = 16
	ADS_RIGHT_DS_WRITE_PROP     = 32
	ADS_RIGHT_DS_SELF           = 8
)

// SYSTEM_MANDATORY_LABEL_ACE MASK
const (
	SYSTEM_MANDATORY_LABEL_NO_WRITE_UP   = 1
	SYSTEM_MANDATORY_LABEL_NO_READ_UP    = 2
	SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP = 4
)

var ControlAccess = map[string]string{
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
	"b1b3a417-ec55-4191-b327-b72e33e38af2": "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity",
	"bf967918-0de6-11d0-a285-00aa003049e2": "Admin-Count",
	"6da8a4fe-0e52-11d0-a286-00aa003049e2": "Auditing-Policy",
	"bf967932-0de6-11d0-a285-00aa003049e2": "CA-Certificate",
	"963d2740-48be-11d1-a9c3-0000f80367c1": "CA-Certificate-DN",
	"2a39c5b1-8960-11d1-aebc-0000f80367c1": "Certificate-Templates",
	"800d94d7-b7a1-42a1-b14d-7cae1423d07f": "ms-DS-Allowed-To-Delegate-To",
}

type ACE_HEADER struct {
	AceType  uint8  `json:"ace_type" bson:"ace_type"`   //ace 类型
	AceFlags uint8  `json:"ace_flags" bson:"ace_flags"` //ace 标签
	AceSize  uint16 `json:"ace_size" bson:"ace_size"`   //ace 大小
}

func NewAceHeader() *ACE_HEADER {
	return &ACE_HEADER{}
}

func (header *ACE_HEADER) ReadBytes(msg []byte) *ACE_HEADER {
	binary.Read(bytes.NewReader(msg[:1]), binary.LittleEndian, &header.AceType)
	binary.Read(bytes.NewReader(msg[1:2]), binary.LittleEndian, &header.AceFlags)
	binary.Read(bytes.NewReader(msg[2:4]), binary.LittleEndian, &header.AceSize)
	return header
}

type Ace interface {
	// 从byte数组中解析为ace对象
	ReadBytes(msg []byte) Ace
	// 将ace对象以String方式输出
	String() string
	// 从sddl string中转化为ace对象
	ReadString(param []string, domain string) Ace

	// 读取ACE权限选项
	GetMask() []string
	GetRawMask() uint32
	// 读取sid
	GetSid() *SID
	// 读取flags标志
	GetAceFlags() uint8
	// 读取ACE类型
	GetAceType() int
	// 读取ObjectType
	GetAceObjectType() string
	// 读取InheritedObjectType
	GetAceInheritedObjectType() string
}

type AccessAce struct {
	*ACE_HEADER
	Mask uint32 //权限列表
	Sid  *SID   //受托人的SID
}

func NewAccessAce(header *ACE_HEADER) *AccessAce {
	return &AccessAce{
		ACE_HEADER: header,
		Sid:        NewSID(),
	}
}

func (a *AccessAce) GetMask() []string {
	if a.Mask == 0 {
		return nil
	} else {
		return getAceRights(a.Mask)
	}
}

func (a *AccessAce) GetRawMask() uint32 {
	return a.Mask
}

func (a *AccessAce) GetAceFlags() uint8 {
	return a.AceFlags
}

func (a *AccessAce) GetAceType() int {
	return 0
}

func (a *AccessAce) GetSid() *SID {
	return a.Sid
}

func (a *AccessAce) GetAceObjectType() string {
	return ""
}

func (a *AccessAce) GetAceInheritedObjectType() string {
	return ""
}

func (a *AccessAce) ReadBytes(msg []byte) Ace {
	binary.Read(bytes.NewBuffer(msg[:4]), binary.LittleEndian, &a.Mask)
	a.Sid = a.Sid.ReadBytes(msg[4:])
	return a
}

func (a *AccessAce) ReadString(param []string, domain string) Ace {
	a.ACE_HEADER.AceType = ACCESS_DENIED_ACE_TYPE
	// ace-flag-string decode
	for i := 0; i < len(param[1]); i += 2 {
		for k, v := range AceFlagsMap {
			if v == param[1][i:i+2] {
				a.ACE_HEADER.AceFlags = a.ACE_HEADER.AceFlags | k
			}
		}
	}

	// ace-rights decode
	for i := 0; i < len(param[2]); i += 2 {
		for k, v := range AceRightsMap {
			if v == param[2][i:i+2] {
				a.Mask = a.Mask | k
			}
		}
	}

	a.Sid = NewSID()
	a.Sid.ReadString(param[5], domain)

	a.ACE_HEADER.AceSize += uint16(a.Sid.length)
	a.ACE_HEADER.AceSize += 8

	size_mod := a.ACE_HEADER.AceSize % 4
	if size_mod != 0 {
		a.ACE_HEADER.AceSize += size_mod
	}

	return a
}

func (a *AccessAce) String() string {
	// ace = "(" ace-type ";" [ace-flag-string] ";" ace-rights ";" [object-guid] ";" [inherit-object-guid] ";" sid-string ")"
	return fmt.Sprintf("(%s;%s;%s;%s;%s;%s)", AceTypeMap[a.AceType], getAceFlagsStr(a.AceFlags), strings.Join(getAceRights(a.Mask), ""), "", "", a.Sid)
}

type AccessObjectAce struct {
	*ACE_HEADER
	Mask                uint32
	Flags               uint32
	ObjectType          string
	InheritedObjectType string
	Sid                 *SID
}

func NewAccessObjectAce(header *ACE_HEADER) *AccessObjectAce {
	return &AccessObjectAce{
		ACE_HEADER: header,
		Sid:        NewSID(),
	}
}

func (a *AccessObjectAce) GetMask() []string {
	if a.Mask == 0 {
		return nil
	} else {
		return getAceRights(a.Mask)
	}
}

func (a *AccessObjectAce) GetRawMask() uint32 {
	return a.Mask
}

func (a *AccessObjectAce) GetAceFlags() uint8 {
	return a.AceFlags
}

func (a *AccessObjectAce) GetAceType() int {
	return 5
}

func (a *AccessObjectAce) GetSid() *SID {
	return a.Sid
}

func (a *AccessObjectAce) GetAceObjectType() string {
	return a.ObjectType
}

func (a *AccessObjectAce) GetAceInheritedObjectType() string {
	return a.InheritedObjectType
}

func (a *AccessObjectAce) ReadBytes(msg []byte) Ace {
	binary.Read(bytes.NewReader(msg[:4]), binary.LittleEndian, &a.Mask)
	binary.Read(bytes.NewReader(msg[4:8]), binary.LittleEndian, &a.Flags)

	switch a.Flags {
	case 0:
		a.Sid = a.Sid.ReadBytes(msg[8:])
	case 1:
		a.ObjectType = ByteToGUID(msg[8:24])
		a.Sid = a.Sid.ReadBytes(msg[24:])
	case 2:
		a.InheritedObjectType = ByteToGUID(msg[8:24])
		a.Sid = a.Sid.ReadBytes(msg[24:])
	case 3:
		a.ObjectType = ByteToGUID(msg[8:24])
		a.InheritedObjectType = ByteToGUID(msg[24:40])
		a.Sid = a.Sid.ReadBytes(msg[40:])
	}

	return a
}

func (a *AccessObjectAce) String() string {
	// ace = "(" ace-type ";" [ace-flag-string] ";" ace-rights ";" [object-guid] ";" [inherit-object-guid] ";" sid-string ")"
	return fmt.Sprintf("(%s;%s;%s;%s;%s;%s)", AceTypeMap[a.AceType], getAceFlagsStr(a.AceFlags), strings.Join(getAceRights(a.Mask), ""), a.ObjectType, a.InheritedObjectType, a.Sid)
}

func (a *AccessObjectAce) ReadString(param []string, domain string) Ace {
	a.ACE_HEADER.AceType = ACCESS_ALLOWED_OBJECT_ACE_TYPE
	// ace-flag-string decode
	for i := 0; i < len(param[1]); i += 2 {
		for k, v := range AceFlagsMap {
			if v == param[1][i:i+2] {
				a.ACE_HEADER.AceFlags = a.ACE_HEADER.AceFlags | k
			}
		}
	}

	// ace-rights decode
	for i := 0; i < len(param[1]); i += 2 {
		for k, v := range AceRightsMap {
			if v == param[1][i:i+2] {
				a.Mask = a.Mask | k
			}
		}
	}

	a.ObjectType = param[3]
	a.InheritedObjectType = param[4]
	if a.ObjectType != "" {
		a.Flags = a.Flags | 1
	}
	if a.InheritedObjectType != "" {
		a.Flags = a.Flags | 2
	}
	a.Sid = NewSID()
	a.Sid.ReadString(param[5], domain)

	if a.ObjectType != "" {
		a.ACE_HEADER.AceSize += 16
	}
	if a.InheritedObjectType != "" {
		a.ACE_HEADER.AceSize += 16
	}
	a.ACE_HEADER.AceSize += uint16(a.Sid.length)
	a.ACE_HEADER.AceSize += 12

	size_mod := a.ACE_HEADER.AceSize % 4
	if size_mod != 0 {
		a.ACE_HEADER.AceSize += size_mod
	}

	return a
}

/*
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb
Access_Allowed_Ace 定义了DACL的ACE
*/

type AccessAllowedAce struct {
	AccessAce
}

func NewAccessAllowAce(header *ACE_HEADER) *AccessAllowedAce {
	return &AccessAllowedAce{
		AccessAce: AccessAce{
			ACE_HEADER: header,
			Sid:        NewSID(),
		},
	}
}

func (a *AccessAllowedAce) GetAceType() int {
	return ACCESS_ALLOWED_ACE_TYPE
}

/*
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
*/
type AccessAllowedObjectAce struct {
	AccessObjectAce
}

func NewAccessAllowedObjectAce(header *ACE_HEADER) *AccessAllowedObjectAce {
	return &AccessAllowedObjectAce{
		AccessObjectAce: AccessObjectAce{
			ACE_HEADER: header,
			Sid:        NewSID(),
		},
	}
}

func (a *AccessAllowedObjectAce) GetAceType() int {
	return ACCESS_ALLOWED_OBJECT_ACE_TYPE
}

func (a *AccessAllowedObjectAce) GetInheritedObjectType() string {
	return a.InheritedObjectType
}

func (a *AccessAllowedObjectAce) GetObjectType() string {
	return a.ObjectType
}

/*
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/b1e1321d-5816-4513-be67-b65d8ae52fe8
*/

type AccessDeniedAce struct {
	AccessAce
}

func NewAccessDeniedAce(header *ACE_HEADER) *AccessDeniedAce {
	return &AccessDeniedAce{
		AccessAce: AccessAce{
			ACE_HEADER: header,
			Sid:        NewSID(),
		},
	}
}

func (a *AccessDeniedAce) GetAceType() int {
	return ACCESS_DENIED_ACE_TYPE
}

/*
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/8720fcf3-865c-4557-97b1-0b3489a6c270
*/

type AccessDeniedObjectAce struct {
	AccessObjectAce
}

func NewAccessDeniedObjectAce(header *ACE_HEADER) *AccessDeniedObjectAce {
	return &AccessDeniedObjectAce{
		AccessObjectAce: AccessObjectAce{
			ACE_HEADER: header,
			Sid:        NewSID(),
		},
	}
}

func (a *AccessDeniedObjectAce) GetAceType() int {
	return ACCESS_DENIED_OBJECT_ACE_TYPE
}

/*
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/9431fd0f-5b9a-47f0-b3f0-3015e2d0d4f9
*/

type SystemAuditAce struct {
	AccessAce
}

func NewSystemAuditAce(header *ACE_HEADER) *SystemAuditAce {
	return &SystemAuditAce{
		AccessAce: AccessAce{
			ACE_HEADER: header,
			Sid:        NewSID(),
		},
	}
}

func (s *SystemAuditAce) GetAceType() int {
	return SYSTEM_AUDIT_ACE_TYPE
}

/*
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c8da72ae-6b54-4a05-85f4-e2594936d3d5
*/

type SystemAuditObjectAce struct {
	AccessObjectAce
}

func NewSystemAuditObjectAce(header *ACE_HEADER) *SystemAuditObjectAce {
	return &SystemAuditObjectAce{
		AccessObjectAce: AccessObjectAce{
			ACE_HEADER: header,
			Sid:        NewSID(),
		},
	}
}

func (s *SystemAuditObjectAce) GetAceType() int {
	return SYSTEM_AUDIT_OBJECT_ACE_TYPE
}

/*
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/25fa6565-6cb0-46ab-a30a-016b32c4939a
*/

type SystemMandatoryLabelAce struct {
	AccessAce
}

func NewSystemMandatoryLabelAce(header *ACE_HEADER) *SystemMandatoryLabelAce {
	return &SystemMandatoryLabelAce{
		AccessAce: AccessAce{
			ACE_HEADER: header,
			Sid:        NewSID(),
		},
	}
}

func (s *SystemMandatoryLabelAce) GetAceType() int {
	return SYSTEM_MANDATORY_LABEL_ACE_TYPE
}

func getAceFlagsStr(ace_flags uint8) string {
	var result = make([]string, 0)
	for k, v := range AceFlagsMap {
		if ace_flags&k == k {
			result = append(result, v)
		}
	}

	return strings.Join(result, "")
}

func getAceRights(ace_rights uint32) []string {
	var result = make([]string, 0)

	for k, v := range AceRightsMap {
		if ace_rights&k == k {
			result = append(result, v)
		}
	}

	return result
}
