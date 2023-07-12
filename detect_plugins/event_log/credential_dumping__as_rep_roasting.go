/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2021-08-17 10:18:54
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-02-10 12:47:14
 */
package system_plugin

import (
	domain2 "iatp/common/domain"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"

	"fmt"
	"iatp/tools"
	"strings"
)

/*
AS-REP Roasting 检测
1. 检测票据加密类型为弱加密
2. 不需要kerberos预身份验证
*/

func init() {
	detect_plugins.RegisterPlugin(4768, NewAsRepRoasting())
}

type AsRepRoasting struct {
	*detect_plugins.SystemPlugin
}

func NewAsRepRoasting() *AsRepRoasting {
	return &AsRepRoasting{
		&detect_plugins.SystemPlugin{
			PluginName:    "AS-REP Abnormal Response",
			PluginDesc:    "AS-REP 异常的流量请求",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (apr *AsRepRoasting) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	Status := tools.Interface2String(log.WinLog.EventData["Status"])
	TicketEncryptionType := tools.Interface2String(log.WinLog.EventData["TicketEncryptionType"])

	if Status != "0x0" {
		return nil
	}
	if TicketEncryptionType == "0xFFFFFFFF" || TicketEncryptionType == "0xffffffff" {
		return nil
	}

	IpAddress := strings.TrimLeft(tools.Interface2String(log.WinLog.EventData["IpAddress"]), ":ffff:")
	TargetDomainName := domain2.FormatNetBiosDomain(tools.Interface2String(log.WinLog.EventData["TargetDomainName"]))
	TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
	PreAuthType := tools.Interface2String(log.WinLog.EventData["PreAuthType"])

	formData := detect_plugins.AlarmTuples{
		Attacker:            "-",
		AttackerWorkStation: IpAddress,
		Victim:              TargetUserName,
		VictimWorkStation:   "-",
	}

	var desc string
	var level string

	if TicketEncryptionType != "0x11" && TicketEncryptionType != "0x12" {
		if PreAuthType == "0" {
			if value, ok := EncryptionType[TicketEncryptionType]; !ok {
				desc = fmt.Sprintf("发现来自%s请求了一个不需要预身份验证的%s(%s)账户的TGT票据，并且使用%s(未知算法)", IpAddress, TargetUserName, TargetDomainName, TicketEncryptionType)
			} else {
				desc = fmt.Sprintf("发现来自%s请求了一个不需要预身份验证的%s(%s)账户的TGT票据，并且使用%s(弱算法)", IpAddress, TargetUserName, TargetDomainName, value)
			}
			level = "high"
		} else {
			if value, ok := EncryptionType[TicketEncryptionType]; !ok {
				desc = fmt.Sprintf("发现来自%s使用%s(未知算法)请求了%s(%s)账户的TGT票据", IpAddress, TicketEncryptionType, TargetUserName, TargetDomainName)
			} else {
				desc = fmt.Sprintf("发现来自%s使用%s(弱算法)请求了%s(%s)账户的TGT票据", IpAddress, value, TargetUserName, TargetDomainName)
			}
			level = "high"
		}
		return detect_plugins.NewPluginAlarm(level, desc, "CredentialDumping", "T1110.001", log, apr, formData)
	}

	if PreAuthType == "0" {
		desc = fmt.Sprintf("发现来自%s请求了一个不需要预身份验证的%s(%s)账户的TGT票据", IpAddress, TargetUserName, TargetDomainName)
		level = "high"
		return detect_plugins.NewPluginAlarm(level, desc, "CredentialDumping", "T1110.001", log, apr, formData)
	}

	return nil
}
