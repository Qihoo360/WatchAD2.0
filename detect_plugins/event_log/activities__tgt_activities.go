package system_plugin

import (
	"fmt"
	domain2 "iatp/common/domain"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/tools"
	"strings"
)

/*
TGT 票据申请活动
*/

func init() {
	detect_plugins.RegisterPlugin(4768, NewTGTActivities())
}

type TGTActivities struct {
	*detect_plugins.SystemPlugin
}

func NewTGTActivities() *TGTActivities {
	return &TGTActivities{
		&detect_plugins.SystemPlugin{
			PluginName:    "TGT Activities",
			PluginDesc:    "TGT 票据相关活动",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (tgtActivities *TGTActivities) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	IpAddress := strings.TrimLeft(tools.Interface2String(log.WinLog.EventData["IpAddress"]), ":ffff:")
	TargetDomainName := domain2.FormatNetBiosDomain(tools.Interface2String(log.WinLog.EventData["TargetDomainName"]))
	TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
	Status := tools.Interface2String(log.WinLog.EventData["Status"])

	form_data := detect_plugins.CreateAlarmTuples("-", IpAddress, TargetUserName, "-")

	var desc string
	var level string

	switch Status {
	// case "0x6":
	// 用户名不存在,查看同一IP多次请求不同且不存在的账户
	// if abnormal, result := database.UniqueIncreaseCacheAbnormal("tgt_activities"+IpAddress, TargetUserName, 10, 1*60); abnormal {
	// 	desc = fmt.Sprintf("发现来自%s多次请求不存在用户的TGT票据，可能为账户枚举攻击", Time.Format(time.RFC3339), IpAddress)
	// 	keys := tools.GetAllKeyFromMap(func(m map[string]int) map[interface{}]interface{} {
	// 		mi := make(map[interface{}]interface{})
	// 		for k, v := range m {
	// 			mi[k] = v
	// 		}
	// 		return mi
	// 	}(result))
	// 	targetUsers := make([]string, 0, len(keys))
	// 	for _, v := range keys {
	// 		targetUsers = append(targetUsers, v.(string))
	// 	}
	// 	formData.Victim = strings.Join(targetUsers, ",")
	// 	return tgtActivities.CreateAlert("high", desc, formData, log)
	// }
	case "0xC":
		// 请求的开始时间晚于结束时间
		d, err := domain2.NewDomain(TargetDomainName)
		if err == nil {
			if d.IsHighRiskAccount(TargetUserName) {
				desc = fmt.Sprintf("发现来自%s请求敏感账户%s(%s)TGT票据的开始时间晚于结束时间", IpAddress, TargetUserName, TargetDomainName)
				return detect_plugins.NewPluginAlarm("high", desc, "activities", "", log, tgtActivities, *form_data)
			}
		}

	case "0x22":
		// 请求重播
		desc = fmt.Sprintf("发现来自%s重播%s(%s)的TGT票据", IpAddress, TargetUserName, TargetDomainName)
		return detect_plugins.NewPluginAlarm("high", desc, "activities", "", log, tgtActivities, *form_data)
	case "0x29":
		//校验和不匹配
		desc = fmt.Sprintf("发现来自%s请求%s(%s)的TGT票证出现0x29错误, 身份验证数据在传输过程中被篡改", IpAddress, TargetUserName, TargetDomainName)
		d, err := domain2.NewDomain(TargetDomainName)
		if err == nil {
			if d.IsHighRiskAccount(TargetUserName) {
				level = "high"
			}
		}

		level = "medium"

		return detect_plugins.NewPluginAlarm(level, desc, "activities", "", log, tgtActivities, *form_data)
	}
	return nil
}
