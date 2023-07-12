package sddl

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strings"
)

var AclRegexp *regexp.Regexp

func init() {
	AclRegexp = regexp.MustCompile(`([A-Z]{1,})(.*)`)
}

type ACL struct {
	AclRevision uint8
	Sbz1        uint8
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
	Aces        []Ace
}

func NewAcl() *ACL {
	return &ACL{
		Aces: make([]Ace, 0),
	}
}

func (acl *ACL) ReadBytes(msg []byte) *ACL {
	binary.Read(bytes.NewReader(msg[:1]), binary.LittleEndian, &acl.AclRevision)
	binary.Read(bytes.NewReader(msg[1:2]), binary.LittleEndian, &acl.Sbz1)
	binary.Read(bytes.NewReader(msg[2:4]), binary.LittleEndian, &acl.AclSize)
	binary.Read(bytes.NewReader(msg[4:6]), binary.LittleEndian, &acl.AceCount)
	binary.Read(bytes.NewReader(msg[6:8]), binary.LittleEndian, &acl.Sbz2)

	var loop int
	var ace Ace
	msg = msg[8:]

	for loop < int(acl.AceCount) {
		ace_header := NewAceHeader()
		ace_header.ReadBytes(msg[:4])

		switch ace_header.AceType {
		case ACCESS_ALLOWED_ACE_TYPE:
			ace = NewAccessAllowAce(ace_header)
		case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
			ace = NewAccessAllowedObjectAce(ace_header)
		case ACCESS_DENIED_ACE_TYPE:
			ace = NewAccessDeniedAce(ace_header)
		case ACCESS_DENIED_OBJECT_ACE_TYPE:
			ace = NewAccessDeniedAce(ace_header)
		case SYSTEM_AUDIT_ACE_TYPE:
			ace = NewSystemAuditAce(ace_header)
		case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
			ace = NewSystemAuditObjectAce(ace_header)
		}

		if ace != nil {
			ace.ReadBytes(msg[4:])
			acl.Aces = append(acl.Aces, ace)
		}

		msg = msg[ace_header.AceSize:]
		loop = loop + 1
	}

	return acl
}

func (acl *ACL) ReadString(msg, domain string) *ACL {
	var ace Ace
	aclParam := AclRegexp.FindStringSubmatch(msg)[1:]

	aces := regexp.MustCompile(`\((.*?)\)`).FindAllStringSubmatch(aclParam[1], -1)

	for _, v := range aces {
		aceParam := strings.Split(v[1], ";")
		switch aceParam[0] {
		case "OA":
			ace = NewAccessAllowedObjectAce(NewAceHeader())
		case "D":
			ace = NewAccessDeniedAce(NewAceHeader())
		case "AU":
			ace = NewSystemAuditAce(NewAceHeader())
		case "A":
			ace = NewAccessAllowAce(NewAceHeader())
		case "OD":
			ace = NewAccessDeniedObjectAce(NewAceHeader())
		case "OU":
			ace = NewSystemAuditObjectAce(NewAceHeader())
		}
		ace.ReadString(aceParam, domain)
		acl.Aces = append(acl.Aces, ace)
	}
	return acl
}

func (acl *ACL) String() string {
	var ace_str = make([]string, 0)

	for _, ace := range acl.Aces {
		ace_str = append(ace_str, ace.String())
	}

	return strings.Join(ace_str, "")
}
