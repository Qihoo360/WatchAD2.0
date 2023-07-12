package system_plugin

import (
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"

	"fmt"
	"iatp/tools"
)

func init() {
	detect_plugins.RegisterPlugin(4794, NewDSRMChange())
}

type DSRMChange struct {
	*detect_plugins.SystemPlugin
}

func NewDSRMChange() *DSRMChange {
	return &DSRMChange{
		&detect_plugins.SystemPlugin{
			PluginName:    "DSRM Change",
			PluginDesc:    "DSRM 密码重置",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (d *DSRMChange) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
	Workstation := tools.Interface2String(log.WinLog.EventData["Workstation"])

	desc := fmt.Sprintf("发现 %s(%s) 账号 重置了 %s 域控的DSRM密码",
		SubjectUserName, SubjectDomainName, Workstation)

	form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", "-", Workstation)
	return detect_plugins.NewPluginAlarm("high", desc, "Persistence", "", log, d, *form_data)
}
