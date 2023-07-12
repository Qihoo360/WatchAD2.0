package gpo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"golang.org/x/text/encoding/unicode"
)

type AAS struct {
	Header         header         `json:"header"`
	ProductInfo    productInfo    `json:"product_info"`
	ProductPublish productPublish `json:"product_publish"`
	End            end            `json:"end"`
}

type header struct {
	Signature          uint32 `json:"signature"`
	Version            uint32 `json:"version"`
	TimeStamp          uint32 `json:"time_stamp"`
	LangId             uint32 `json:"land_id"`
	Platform           uint32 `json:"platform"`
	ScriptType         uint32 `json:"script_type"`
	ScriptMajorVersion uint32 `json:"script_major_version"`
	ScriptMinorVersion uint32 `json:"script_minor_version"`
	ScriptAttributes   uint32 `json:"script_attributes"`
}

type productInfo struct {
	ProductKey             string `json:"product_key"`
	ProductName            string `json:"product_name"`
	PackageName            string `json:"package_name"`
	Language               uint32 `json:"language"`
	Version                uint32 `json:"version"`
	Assignment             uint32 `json:"assignment"`
	ObsoleteArg            uint32 `json:"obsolete_arg"`
	ProductIcon            string `json:"product_icon"`
	PackageMediaPath       string `json:"package_media_path"`
	PackageCode            string `json:"package_code"`
	_unknown_1             string
	_unknown_2             string
	InstanceType           uint32 `json:"instance_type"`
	LUASetting             uint32 `json:"lua_setting"`
	RemoteURTInstalls      uint32 `json:"remote_urt_installs"`
	ProductDeploymentFlags uint32 `json:"product_deployment_flags"`
}

type sourceListPublish struct {
	PatchCode          string `json:"path_code"`
	PatchPackageName   string `json:"patch_package_name"`
	DiskPromptTemplate string `json:"disk_prompt_template"`
	PackagePath        string `json:"package_path"`
	NumberOfDisks      uint32 `json:"number_of_disks"`
	Disks              []disk `json:"disks"`
	LaunchPath         string `json:"launch_path"`
}

type disk struct {
	DiskId     uint32 `json:"disk_id"`
	VolumeName string `json:"volume_name"`
	DiskPrompt string `json:"disk_prompt"`
}

type productPublish struct {
	PackageKey        string            `json:"package_key"`
	SourceListPublish sourceListPublish `json:"source_list_publish"`
}

type end struct {
	CheckSum            uint32 `json:"check_sum"`
	ProgressTotalHDWord uint32 `json:"progress_total_hd_word"`
	ProgressTotalLDWord uint32 `json:"progress_total_ld_Word"`
}

func NewAAS() *AAS {
	return &AAS{}
}

// TODO: 错误异常处理
func (a *AAS) Decode(msg []byte) {
	if !bytes.Equal(msg[:2], []byte{2, 9}) {
		return
	}
	offset := 2

	// Header: 0x02 0x09 Arguments
	offset, _ = a.decoderHeader(msg, offset)

	// 搜索 ProductInfo
	for i := 0; i < len(msg[offset:]); i++ {
		if bytes.Equal(msg[offset+i:offset+i+2], []byte{4, 16}) {
			offset += i

			// ProductInfo: 0x04 0x10 Arguments
			if product_info_offset, err := a.decoderProductInfo(msg, offset+2); err != nil {
				continue
			} else {
				offset = product_info_offset
				break
			}
		}
	}

	// 搜索 ProductPublish
	for i := 0; i < len(msg[offset:]); i++ {
		if bytes.Equal(msg[offset+i:offset+i+2], []byte{16, 1}) {
			offset += i

			if product_publish_offset, err := a.decoderProductPublish(msg, offset+2); err != nil {
				continue
			} else {
				offset = product_publish_offset
				break
			}
		}
	}

	// 搜索
	for i := 0; i < len(msg[offset:]); i++ {
		if bytes.Equal(msg[offset+i:offset+i+7], []byte{9, 0, 128, 0, 128, 0, 128}) {
			offset += i
			// SourceListPublish
			if source_list_publish_offset, err := a.deocderSourceListPublish(msg, offset+1); err != nil {
				continue
			} else {
				offset = source_list_publish_offset
				break
			}
		}
	}

	// 搜索
	for i := 0; i < len(msg[offset:]); i++ {
		if bytes.Equal(msg[offset+i:offset+i+2], []byte{3, 3}) {
			offset += i

			if _, err := a.decoderEnd(msg, offset+2); err != nil {
				continue
			} else {
				break
			}
		}
	}
}

func (a *AAS) decoderEnd(msg []byte, offset int) (int, error) {
	var ok bool

	data, offset := getData(msg, offset)
	if a.End.CheckSum, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.End.ProgressTotalHDWord, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.End.ProgressTotalLDWord, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	return offset, nil
}

func (a *AAS) decoderProductPublish(msg []byte, offset int) (int, error) {
	var ok bool
	var tmp []byte

	data, offset := getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}

	a.ProductPublish.PackageKey = string(tmp)
	return offset, nil
}

func (a *AAS) deocderSourceListPublish(msg []byte, offset int) (int, error) {
	var ok bool
	var tmp []byte

	data, offset := getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductPublish.SourceListPublish.PatchCode = string(tmp)

	data, offset = getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductPublish.SourceListPublish.PatchPackageName = string(tmp)

	data, offset = getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductPublish.SourceListPublish.DiskPromptTemplate = string(tmp)

	data, offset = getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductPublish.SourceListPublish.PackagePath = string(tmp)

	data, offset = getData(msg, offset)
	if a.ProductPublish.SourceListPublish.NumberOfDisks, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	a.ProductPublish.SourceListPublish.Disks = make([]disk, 0)

	for i := 0; i < int(a.ProductPublish.SourceListPublish.NumberOfDisks); i++ {
		data, offset = getData(msg, offset)
		disk_id, ok := data.(uint32)
		if !ok {
			return 0, errors.New("格式转换错误")
		}

		data, offset = getData(msg, offset)
		tmp, ok := data.([]byte)
		var volume_name string
		if !ok {
			return 0, errors.New("格式转换错误")
		} else {
			volume_name = string(tmp)
		}

		data, offset = getData(msg, offset)
		tmp, ok = data.([]byte)
		var disk_prompt string
		if !ok {
			return 0, errors.New("格式转换错误")
		} else {
			disk_prompt = string(tmp)
		}

		a.ProductPublish.SourceListPublish.Disks = append(a.ProductPublish.SourceListPublish.Disks, disk{
			DiskId:     disk_id,
			VolumeName: volume_name,
			DiskPrompt: disk_prompt,
		})
	}

	data, offset = getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductPublish.SourceListPublish.LaunchPath = string(tmp)

	return offset, nil
}

func (a *AAS) decoderHeader(msg []byte, offset int) (int, error) {
	var ok bool

	data, offset := getData(msg, offset)
	if a.Header.Signature, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.Header.Version, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.Header.TimeStamp, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.Header.LangId, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.Header.Platform, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.Header.ScriptType, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.Header.ScriptMajorVersion, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.Header.ScriptMinorVersion, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.Header.ScriptAttributes, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	return offset, nil
}

func (a *AAS) decoderProductInfo(msg []byte, offset int) (int, error) {
	var ok bool
	var tmp []byte

	data, offset := getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductInfo.ProductKey = string(tmp)

	data, offset = getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductInfo.ProductName = string(tmp)

	data, offset = getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductInfo.PackageName = string(tmp)

	data, offset = getData(msg, offset)
	if a.ProductInfo.Language, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.ProductInfo.Version, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.ProductInfo.Assignment, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.ProductInfo.ObsoleteArg, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductInfo.ProductIcon = string(tmp)

	data, offset = getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductInfo.PackageMediaPath = string(tmp)

	data, offset = getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductInfo.PackageCode = string(tmp)

	data, offset = getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductInfo._unknown_1 = string(tmp)

	data, offset = getData(msg, offset)
	if tmp, ok = data.([]byte); !ok {
		return 0, errors.New("格式转换错误")
	}
	a.ProductInfo._unknown_2 = string(tmp)

	data, offset = getData(msg, offset)
	if a.ProductInfo.InstanceType, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.ProductInfo.LUASetting, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.ProductInfo.RemoteURTInstalls, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	data, offset = getData(msg, offset)
	if a.ProductInfo.ProductDeploymentFlags, ok = data.(uint32); !ok {
		return 0, errors.New("格式转换错误")
	}

	return offset, nil
}

func getData(msg []byte, offset int) (interface{}, int) {
	dataType := msg[offset : offset+2]

	switch {
	// 32-bit signed integer
	case bytes.Equal(dataType, []byte{0, 64}):
		return binary.LittleEndian.Uint32(msg[offset+2 : offset+6]), 6 + offset

	// null string
	case bytes.Equal(dataType, []byte{0, 0}):
		return []byte{}, 2 + offset

	// null argument
	case bytes.Equal(dataType, []byte{0, 128}):
		return []byte{}, 2 + offset

	// ASCII char string
	case binary.LittleEndian.Uint16(dataType)>>14 == 0:
		dataLen := binary.LittleEndian.Uint16(dataType)
		return msg[offset+2 : offset+2+int(dataLen)], 2 + int(dataLen) + offset

	// binary stream
	case binary.LittleEndian.Uint16(dataType)>>14 == 2:
		dataLen := binary.LittleEndian.Uint16(dataType) - 32768
		return msg[offset+2 : offset+2+int(dataLen)], 2 + int(dataLen) + offset

	// extended size
	case bytes.Equal(dataType, []byte{0, 192}):
		// ASCII char string
		if binary.LittleEndian.Uint32(msg[offset+2:offset+6])>>30 == 0 {
			dataLen := binary.LittleEndian.Uint32(msg[offset+2 : offset+6])
			return msg[offset+6 : offset+6+int(dataLen)], 6 + int(dataLen) + offset
		} else if binary.LittleEndian.Uint32(msg[offset+2:offset+6])>>30 == 2 {
			dataLen := (binary.LittleEndian.Uint32(msg[offset+2:offset+6]) - 2147483648)
			return msg[offset+6 : offset+6+int(dataLen)], 6 + int(dataLen) + offset
		} else {
			log.Println(msg[offset : offset+6])
		}

	// unicode string
	case binary.LittleEndian.Uint16(dataType)>>14 == 3:
		dataLen := binary.LittleEndian.Uint16(dataType) - 49152
		decoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		utf8_byte, _ := decoder.Bytes(msg[offset+2 : offset+2+int(dataLen)])
		return utf8_byte, 2 + int(dataLen) + offset
	}

	return nil, offset + 2
}
