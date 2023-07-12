/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2021-09-08 10:40:38
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-02-10 12:46:58
 */
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
 重置用户账户密码活动行为检测
 1. 记录常规重置密码行为，作为活动事件（告警级别为information）
 2. 针对high risk account账户变动实时告警
*/

func init() {
	detect_plugins.RegisterPlugin(4724, NewResetAccountPassword())
}

type ResetAccountPassword struct {
	*detect_plugins.SystemPlugin
}

func NewResetAccountPassword() *ResetAccountPassword {
	return &ResetAccountPassword{
		&detect_plugins.SystemPlugin{
			PluginName:    "Reset Account Password",
			PluginDesc:    "重置用户账户密码活动",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (resetAccountPasswd *ResetAccountPassword) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	SubjectDomainName := domain2.FormatNetBiosDomain(tools.Interface2String(log.WinLog.EventData["SubjectDomainName"]))
	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	TargetDomainName := domain2.FormatNetBiosDomain(tools.Interface2String(log.WinLog.EventData["TargetDomainName"]))
	TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])

	// 机器账户不检查
	if strings.HasSuffix(TargetUserName, "$") {
		return nil
	}
	if strings.HasSuffix(SubjectUserName, "$") {
		return nil
	}

	// 修改自身密码不检查
	if SubjectUserName == TargetUserName {
		return nil
	}

	formData := detect_plugins.AlarmTuples{
		Attacker:            SubjectUserName,
		AttackerWorkStation: "-", //resetAccountPasswd.GetSourceWorkStation()
		Victim:              TargetUserName,
		VictimWorkStation:   "-",
	}

	// 非 itweb 账户修改用户密码
	if SubjectUserName != "itweb" {
		desc := fmt.Sprintf("发现%s(%s) 账户未通过itweb修改 %s(%s) 账户密码行为", SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName)

		d, err := domain2.NewDomain(TargetDomainName)
		if err == nil {
			if d.IsHighRiskAccount(TargetUserName) {
				return detect_plugins.NewPluginAlarm("high", desc, "activities", "", log, resetAccountPasswd, formData)
			}
		}

		return detect_plugins.NewPluginAlarm("medium", desc, "activities", "", log, resetAccountPasswd, formData)
	}

	// 查询高价值账户修改用户密码
	//var result bson.M
	//if err := mongodb.FindOne(bson.M{fmt.Sprintf("high_risk_name.%s", TargetDomainName): SubjectUserName}).Decode(&result); err == nil {
	//	alertDoc := fmt.Sprintf("发现 %s(%s) 账户 修改高价值账户 %s(%s)的密码行为", SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName)
	//	alert := common.AlertDoc{
	//		PluginName:    PluginName,
	//		PluginDesc:    PluginDesc,
	//		PluginVersion: PluginVersion,
	//		Level:         "high",
	//		AlertDesc:     alertDoc,
	//		FormData:      formData.MustMap(),
	//		RawData:       eventLog.MustMap(),
	//	}
	//	return &alert
	//}

	// 正常事件记录
	desc := fmt.Sprintf("%s(%s) 账户修改 %s(%s) 账户密码", SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName)
	return detect_plugins.NewPluginAlarm("information", desc, "activities", "", log, resetAccountPasswd, formData)
}
