package system_plugin

var EncryptionType = map[string]string{
	"0x1":  "DES-CBC-CRC",
	"0x01": "DES-CBC-CRC",
	"0x3":  "DES-CBC-MD5",
	"0x03": "DES-CBC-MD5",
	"0x11": "AES128-CTS-HMAC-SHA1-96",
	"0x12": "AES256-CTS-HMAC-SHA1-96",
	"0x17": "RC4-HMAC",
	"0x18": "RC4-HMAC-EXP",
}
