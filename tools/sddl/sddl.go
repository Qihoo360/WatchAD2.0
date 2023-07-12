package sddl

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const (
	SR = 0
	RM = 1
	PS = 2
	PD = 3
	SI = 4
	DI = 5
	SC = 6
	DC = 7
	SS = 8
	DT = 9
	SD = 10
	SP = 11
	DD = 12
	DP = 13
	GD = 14
	OD = 15
)

var SddlRegexp *regexp.Regexp

func init() {
	SddlRegexp = regexp.MustCompile(`O:(.*)G:(.*)D:(.*)S:(.*)`)
}

type binstring string

type SDDL struct {
	Control binstring
	Owner   *SID
	Group   *SID
	Sacl    *ACL
	Dacl    *ACL
}

func NewSDDL() *SDDL {
	return &SDDL{
		Owner: NewSID(),
		Group: NewSID(),
		Sacl:  NewAcl(),
		Dacl:  NewAcl(),
	}
}

func (s *SDDL) ReadBytes(msg []byte) *SDDL {
	var control uint16
	binary.Read(bytes.NewReader(msg[2:4]), binary.LittleEndian, &control)
	s.Control = binstring(fmt.Sprintf("%16b", control))

	var OffsetOwner uint32
	binary.Read(bytes.NewReader(msg[4:8]), binary.LittleEndian, &OffsetOwner)

	var OffsetGroup uint32
	binary.Read(bytes.NewReader(msg[8:12]), binary.LittleEndian, &OffsetGroup)

	if OffsetOwner == 0 {
		s.Owner = nil
	} else {
		s.Owner = s.Owner.ReadBytes(msg[OffsetOwner:])
	}

	if OffsetGroup == 0 {
		s.Group = nil
	} else {
		s.Group = s.Group.ReadBytes(msg[OffsetGroup:])
	}

	var OffsetSacl uint32
	binary.Read(bytes.NewReader(msg[12:16]), binary.LittleEndian, &OffsetSacl)

	var OffsetDacl uint32
	binary.Read(bytes.NewReader(msg[16:20]), binary.LittleEndian, &OffsetDacl)

	s.Dacl.ReadBytes(msg[OffsetDacl:])
	s.Sacl.ReadBytes(msg[OffsetSacl:])

	return s
}

func (s *SDDL) ReadSddl(sddl string) *SDDL {
	sddl_param := SddlRegexp.FindStringSubmatch(sddl)[1:]
	control := []string{"1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}

	s.Owner.ReadString(sddl_param[0], "1061169269-3332741925-2608941520")
	s.Group.ReadString(sddl_param[1], "1061169269-3332741925-2608941520")

	if sddl_param[2] != "" {
		daclParam := AclRegexp.FindStringSubmatch(sddl_param[2])[1:]
		control[DP] = "1"

		if strings.Contains(daclParam[0], "P") {
			control[PD] = "1"
		}
		if strings.Contains(daclParam[0], "AR") {
			control[DC] = "1"
		}
		if strings.Contains(daclParam[0], "AI") {
			control[DI] = "1"
		}

		s.Dacl.ReadString(sddl_param[2], "1061169269-3332741925-2608941520")
	}
	if sddl_param[3] != "" {
		saclParam := AclRegexp.FindStringSubmatch(sddl_param[3])[1:]
		control[SP] = "1"
		if strings.Contains(saclParam[0], "P") {
			control[PS] = "1"
		}
		if strings.Contains(saclParam[0], "AR") {
			control[SC] = "1"
		}
		if strings.Contains(saclParam[0], "AI") {
			control[SI] = "1"
		}

		s.Sacl.ReadString(sddl_param[3], "1061169269-3332741925-2608941520")
	}

	s.Control = binstring(strings.Join(control, ""))
	return s
}

func (s *SDDL) Sddl() string {
	// "P" indicates Protected PS or PD flags from that section, "AR" corresponds to SC or DC, and "AI" indicates SI or DI.
	var dacl_flag = make([]string, 0)
	var sacl_flag = make([]string, 0)

	if s.Control[PD] == 49 {
		dacl_flag = append(dacl_flag, "P")
	}
	if s.Control[PS] == 49 {
		sacl_flag = append(sacl_flag, "P")
	}
	if s.Control[DC] == 49 {
		dacl_flag = append(dacl_flag, "AR")
	}
	if s.Control[SC] == 49 {
		sacl_flag = append(sacl_flag, "AR")
	}
	if s.Control[DI] == 49 {
		dacl_flag = append(dacl_flag, "AI")
	}
	if s.Control[SI] == 49 {
		sacl_flag = append(sacl_flag, "AI")
	}

	return fmt.Sprintf(
		"O:%sG:%sD:%s%sS:%s%s",
		s.Owner.String(), s.Group.String(),
		strings.Join(dacl_flag, ""), s.Dacl.String(),
		strings.Join(sacl_flag, ""), s.Sacl.String(),
	)
}

func ByteToGUID(byte_guid []byte) string {
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(reverse(byte_guid[:4])), hex.EncodeToString(reverse(byte_guid[4:6])), hex.EncodeToString(reverse(byte_guid[6:8])), hex.EncodeToString(byte_guid[8:10]), hex.EncodeToString(byte_guid[10:16]))
}

func GUIDToByte(guid string) []byte {
	guid_str := strings.Join(strings.Split(guid, "-"), "")
	guid_byte, _ := hex.DecodeString(guid_str)

	return guid_byte
}

func reverse(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}
