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
kerberoasting 检测行为梳理
event_id:4769
 - 请求敏感的服务票证
 - 单位时间内请求服务票证数超过阈值 (宽泛检测)
 - 监视除0x11和0x12之外的票证加密类型，其他加密类型均属于弱加密

2021-11-05 Update: 将Kerberoasting 弱密钥相关告警降为低级
*/

func init() {
	detect_plugins.RegisterPlugin(4769, NewKerberoasting())
}

type Kerberoasting struct {
	*detect_plugins.SystemPlugin
}

func NewKerberoasting() *Kerberoasting {
	return &Kerberoasting{
		&detect_plugins.SystemPlugin{
			PluginName:    "Kerberoasting",
			PluginDesc:    "kerberoasting 攻击行为",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (kb *Kerberoasting) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	IpAddress := strings.TrimLeft(tools.Interface2String(log.WinLog.EventData["IpAddress"]), ":ffff:")
	TargetDomainName := domain2.FormatNetBiosDomain(tools.Interface2String(log.WinLog.EventData["TargetDomainName"]))
	TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
	TicketEncryptionType := tools.Interface2String(log.WinLog.EventData["TicketEncryptionType"])
	ServiceName := tools.Interface2String(log.WinLog.EventData["ServiceName"])

	// 过滤机器账户
	if strings.HasSuffix(TargetUserName, "$") || strings.HasSuffix(strings.Split(TargetUserName, "@")[0], "$") {
		return nil
	}

	// 测试账户过滤
	domain, err := domain2.NewDomain(TargetDomainName)
	if err == nil && strings.HasPrefix(strings.ToLower(TargetUserName), domain.UserName) {
		return nil
	}

	if TicketEncryptionType == "0xFFFFFFFF" || TicketEncryptionType == "0xffffffff" {
		return nil
	}

	form_data := detect_plugins.CreateAlarmTuples(TargetUserName, IpAddress, ServiceName, "-")
	var desc string
	var level string

	// 使用弱加密方法
	if TicketEncryptionType != "0x11" && TicketEncryptionType != "0x12" {
		if strings.HasPrefix(TargetUserName, ServiceName) {
			return nil
		}

		if value, ok := EncryptionType[TicketEncryptionType]; !ok {
			desc = fmt.Sprintf("发现%s(%s) 账户在请求%s服务的TGS票据中使用了 %s (未知算法)", TargetUserName, TargetDomainName, ServiceName, TicketEncryptionType)
		} else {
			desc = fmt.Sprintf("发现%s(%s) 账户在请求%s服务的TGS票据中使用了 %s (弱算法)", TargetUserName, TargetDomainName, ServiceName, value)
		}
		level = "low"

		// TODO:检测同一个账户请求大量不同账户的TGS票据，则等级升级为高级

		return detect_plugins.NewPluginAlarm(level, desc, "CredentialDumping", "T1110.001", log, kb, *form_data)
	}

	// 请求了敏感的服务票证
	highRiskSpn := tools.GetAllHighRiskSpn()
	if highRiskSpn != nil {
		if _, ok := highRiskSpn[strings.ToLower(ServiceName)]; ok {
			desc = fmt.Sprintf("发现%s(%s) 请求了%s(敏感服务)的TGS票证", TargetUserName, TargetDomainName, ServiceName)
			level = "high"
			return detect_plugins.NewPluginAlarm(level, desc, "CredentialDumping", "", log, kb, *form_data)
		}
	}
	return nil
}
