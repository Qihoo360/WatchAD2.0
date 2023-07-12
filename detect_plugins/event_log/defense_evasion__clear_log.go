package system_plugin

import (
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"

	"fmt"
	"iatp/tools"
)

func init() {
	detect_plugins.RegisterPlugin(1102, NewClearLog())
}

type ClearLog struct {
	*detect_plugins.SystemPlugin
}

func NewClearLog() *ClearLog {
	return &ClearLog{
		&detect_plugins.SystemPlugin{
			PluginName:    "Clear Log",
			PluginDesc:    "系统日志清除",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (c *ClearLog) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])

	desc := fmt.Sprintf("发现 %s(%s) 账号 清除了 %s 域控的日志",
		SubjectUserName, SubjectDomainName, log.WinLog.ComputerName)

	formData := detect_plugins.AlarmTuples{
		Attacker:            SubjectUserName,
		AttackerWorkStation: "-",
		Victim:              "-",
		VictimWorkStation:   log.WinLog.ComputerName,
	}

	return detect_plugins.NewPluginAlarm("high", desc, "DefenseEvasion", "", log, c, formData)
}
