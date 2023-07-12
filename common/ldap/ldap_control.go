package ldap_tool

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	LDAP_SERVER_SD_FLAGS_OID     = "1.2.840.113556.1.4.801"
	LDAP_SERVER_NOTIFICATION_OID = "1.2.840.113556.1.4.528"
)

type ControlSDFlagsOID struct {
	Flags uint32
}

// GetControlType returns the OID
func (c *ControlSDFlagsOID) GetControlType() string {
	return LDAP_SERVER_SD_FLAGS_OID
}

// Encode returns the ber packet representation
func (c *ControlSDFlagsOID) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, LDAP_SERVER_SD_FLAGS_OID, "Control Type (LDAP_SERVER_SD_FLAGS_OID)"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Paging)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c.Flags), "Paging Size"))
	p2.AppendChild(seq)

	packet.AppendChild(p2)
	return packet
}

// String returns a human-readable description
func (c *ControlSDFlagsOID) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)",
		"LDAP_SERVER_SD_FLAGS_OID",
		"1.2.840.113556.1.4.801")
}

type ControlNotification struct {
	Criticality bool
}

// GetControlType returns the OID
func (c *ControlNotification) GetControlType() string {
	return LDAP_SERVER_NOTIFICATION_OID
}

// Encode returns the ber packet representation
func (c *ControlNotification) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, LDAP_SERVER_NOTIFICATION_OID, "Control Type (LDAP_SERVER_NOTIFICATION_OID)"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))
	return packet
}

// String returns a human-readable description
func (c *ControlNotification) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q) Criticality: %t",
		"LDAP_SERVER_NOTIFICATION_OID",
		"1.2.840.113556.1.4.528",
		c.Criticality)
}
