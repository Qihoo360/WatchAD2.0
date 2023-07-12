package sddl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"strings"
)

/*
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
*/

var (
	NULL_SID_AUTHORITY                  = []byte{0, 0, 0, 0, 0, 0}
	WORLD_SID_AUTHORITY                 = []byte{0, 0, 0, 0, 0, 1}
	LOCAL_SID_AUTHORITY                 = []byte{0, 0, 0, 0, 0, 2}
	CREATOR_SID_AUTHORITY               = []byte{0, 0, 0, 0, 0, 3}
	NON_UNIQUE_AUTHORITY                = []byte{0, 0, 0, 0, 0, 4}
	SECURITY_NT_AUTHORITY               = []byte{0, 0, 0, 0, 0, 5}
	SECURITY_APP_PACKAGE_AUTHORITY      = []byte{0, 0, 0, 0, 0, 15}
	SECURITY_MANDATORY_LABEL_AUTHORITY  = []byte{0, 0, 0, 0, 0, 16}
	SECURITY_SCOPED_POLICY_ID_AUTHORITY = []byte{0, 0, 0, 0, 0, 17}
	SECURITY_AUTHENTICATION_AUTHORITY   = []byte{0, 0, 0, 0, 0, 18}
)

var WellKnownSid = map[string]string{
	"S-1-1-0":            "WD",
	"S-1-5-9":            "ED",
	"S-1-5-32-544":       "BA",
	"S-1-5-32-546":       "BG",
	"S-1-5-32-545":       "BU",
	"S-1-5-32-548":       "AO",
	"S-1-5-32-551":       "BO",
	"S-1-5-32-550":       "PO",
	"S-1-5-32-549":       "SO",
	"S-1-5-11":           "AU",
	"S-1-5-10":           "PS",
	"S-1-3-0":            "CO",
	"S-1-3-1":            "CG",
	"S-1-5-18":           "SY",
	"S-1-5-32-547":       "PU",
	"S-1-5-32-552":       "RE",
	"S-1-5-4":            "IU",
	"S-1-5-2":            "NU",
	"S-1-5-6":            "SU",
	"S-1-5-12":           "RC",
	"S-1-5-33":           "WR",
	"S-1-5-7":            "AN",
	"S-1-5-32-554":       "RU",
	"S-1-5-19":           "LS",
	"S-1-5-20":           "NS",
	"S-1-5-32-555":       "RD",
	"S-1-5-32-556":       "NO",
	"S-1-5-32-558":       "MU",
	"S-1-5-32-559":       "LU",
	"S-1-5-32-568":       "IS",
	"S-1-5-32-569":       "CY",
	"S-1-3-4":            "OW",
	"S-1-5-32-573":       "ER",
	"S-1-5-32-574":       "CD",
	"S-1-15-2-1":         "AC",
	"S-1-5-32-575":       "RA",
	"S-1-5-32-576":       "ES",
	"S-1-5-32-577":       "MS",
	"S-1-5-84-0-0-0-0-0": "UD",
	"S-1-5-32-578":       "HA",
	"S-1-5-32-579":       "AA",
	"S-1-5-32-580":       "RM",
	"S-1-16-4096":        "ML",
	"S-1-16-8192":        "ME",
	"S-1-16-8448":        "MP",
	"S-1-16-12288":       "HI",
	"S-1-16-16384":       "SI",
}

var WellKnownDomainSid = map[string]string{
	"-498": "RO",
	"-500": "LA",
	"-501": "LG",
	"-512": "DA",
	"-513": "DU",
	"-514": "DG",
	"-515": "DC",
	"-516": "DD",
	"-517": "CA",
	"-518": "SA",
	"-519": "EA",
	"-520": "PA",
	"-522": "CN",
	"-533": "RS",
}

type SID struct {
	Revision            uint8    `json:"revision" bson:"revision"`                         // 修订版本
	SubAuthorityCount   uint8    `json:"sub_authority_count" bson:"sub_authority_count"`   // SubAuthority 元素个数
	IdentifierAuthority string   `json:"identifier_authority" bson:"identifier_authority"` //
	SubAuthority        []uint32 `json:"sub_authority" bson:"sub_authority_count"`         //
	Sid                 string   `json:"sid" bson:"sid"`                                   // sid 字符串
	length              int
}

func NewSID() *SID {
	return &SID{
		SubAuthority: make([]uint32, 0),
		length:       0,
	}
}

func (sid *SID) ReadBytes(msg []byte) *SID {
	var result uint8
	binary.Read(bytes.NewBuffer(msg[:1]), binary.LittleEndian, &result)
	sid.Revision = result
	binary.Read(bytes.NewBuffer(msg[1:2]), binary.LittleEndian, &result)
	sid.SubAuthorityCount = result

	switch {
	case bytes.Equal(msg[2:8], NULL_SID_AUTHORITY):
		sid.IdentifierAuthority = "S-1-0"
	case bytes.Equal(msg[2:8], WORLD_SID_AUTHORITY):
		sid.IdentifierAuthority = "S-1-1"
	case bytes.Equal(msg[2:8], LOCAL_SID_AUTHORITY):
		sid.IdentifierAuthority = "S-1-2"
	case bytes.Equal(msg[2:8], CREATOR_SID_AUTHORITY):
		sid.IdentifierAuthority = "S-1-3"
	case bytes.Equal(msg[2:8], NON_UNIQUE_AUTHORITY):
		sid.IdentifierAuthority = "S-1-4"
	case bytes.Equal(msg[2:8], SECURITY_NT_AUTHORITY):
		sid.IdentifierAuthority = "S-1-5"
	case bytes.Equal(msg[2:8], SECURITY_APP_PACKAGE_AUTHORITY):
		sid.IdentifierAuthority = "S-1-15"
	case bytes.Equal(msg[2:8], SECURITY_MANDATORY_LABEL_AUTHORITY):
		sid.IdentifierAuthority = "S-1-16"
	case bytes.Equal(msg[2:8], SECURITY_SCOPED_POLICY_ID_AUTHORITY):
		sid.IdentifierAuthority = "S-1-17"
	case bytes.Equal(msg[2:8], SECURITY_AUTHENTICATION_AUTHORITY):
		sid.IdentifierAuthority = "S-1-18"
	}

	sid.length += 8

	var authority uint32
	loop := sid.SubAuthorityCount
	for loop > 0 {
		binary.Read(bytes.NewBuffer(msg[8+4*(sid.SubAuthorityCount-loop):8+4*(sid.SubAuthorityCount-loop+1)]), binary.LittleEndian, &authority)
		sid.SubAuthority = append(sid.SubAuthority, authority)
		loop = loop - 1
		sid.length += 4
	}
	return sid
}

func (sid *SID) ReadString(msg string, domain string) *SID {
	sid.Revision = 1
	if !strings.Contains(msg, "-") {
		for k, v := range WellKnownDomainSid {
			if v == msg {
				msg = fmt.Sprintf("S-1-5-21-%s%s", domain, k)
				goto start_sid_decode
			}
		}

		for k, v := range WellKnownSid {
			if v == msg {
				msg = k
				goto start_sid_decode
			}
		}
	}

start_sid_decode:
	sidParam := strings.Split(msg, "-")
	sid.SubAuthorityCount = uint8(len(sidParam) - 3)
	sid.IdentifierAuthority = strings.Join(sidParam[:3], "-")
	for _, v := range sidParam[3:] {
		subAuth, err := strconv.Atoi(v)
		if err != nil {
			log.Fatal(err.Error())
		} else {
			sid.SubAuthority = append(sid.SubAuthority, uint32(subAuth))
		}
	}

	sid.length = 8 + (len(sidParam)-3)*4
	return sid
}

func (sid *SID) String() string {
	if sid == nil {
		return ""
	}

	var SubAuthoritys []string
	for _, v := range sid.SubAuthority {
		SubAuthoritys = append(SubAuthoritys, strconv.Itoa(int(v)))
	}
	s := fmt.Sprintf("%s-%s", sid.IdentifierAuthority, strings.Join(SubAuthoritys, "-"))

	return s
}

func (sid *SID) FormatString() string {
	s := sid.String()

	if _, ok := WellKnownSid[s]; ok {
		return WellKnownSid[s]
	}

	if strings.HasPrefix(s, "S-1-5-21") {
		for k, v := range WellKnownDomainSid {
			if strings.HasSuffix(s, k) {
				s = v
				break
			}
		}
	}

	return s
}

func (sid *SID) DecodeLen() int {
	return sid.length
}
