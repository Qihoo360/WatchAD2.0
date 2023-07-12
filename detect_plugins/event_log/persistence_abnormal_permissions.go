package system_plugin

import (
	"fmt"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/tools"
	"strings"
)

func init() {
	detect_plugins.RegisterPlugin(4704, NewAbnormalPermission())
}

type AbnormalPermission struct {
	*detect_plugins.SystemPlugin
}

func NewAbnormalPermission() *AbnormalPermission {
	return &AbnormalPermission{
		&detect_plugins.SystemPlugin{
			PluginName:    "Abnormal Permissions",
			PluginDesc:    "可用于持久化的异常权限",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (a *AbnormalPermission) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	PrivilegeList := tools.Interface2String(log.WinLog.EventData["PrivilegeList"])

	if a.check_delegation_privilege(PrivilegeList) {
		SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
		SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
		TargetSid := tools.Interface2String(log.WinLog.EventData["TargetSid"])

		desc := fmt.Sprintf("发现 %s(%s) 账号 赋予了 %s 用户的 SeEnableDelegationPrivilege 权限", SubjectUserName, SubjectDomainName, TargetSid)
		form_data := detect_plugins.CreateAlarmTuples(TargetSid, "-", SubjectUserName, log.WinLog.ComputerName)
		return detect_plugins.NewPluginAlarm("high", desc, "Persistence", "", log, a, *form_data)
	}

	return nil
}

func (a *AbnormalPermission) check_delegation_privilege(privilege string) bool {
	return strings.Contains(privilege, "SeEnableDelegationPrivilege")
}
