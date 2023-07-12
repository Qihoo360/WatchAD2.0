package system_plugin

import (
	"fmt"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/tools"
	"strings"
)

func init() {
	detect_plugins.RegisterPlugin(4648, NewDcSync())
}

type DcSync struct {
	*detect_plugins.SystemPlugin
}

func NewDcSync() *DcSync {
	return &DcSync{
		&detect_plugins.SystemPlugin{
			PluginName:    "DCSync",
			PluginDesc:    "目录服务复制",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (d *DcSync) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	if tools.Interface2String(log.WinLog.EventData["ObjectType"]) != "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}" {
		return nil
	}

	if strings.Contains(tools.Interface2String(log.WinLog.EventData["Properties"]), "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}") {
		SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
		SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])

		desc := fmt.Sprintf("发现%s(%s) 使用dcsync转储了 %s 的凭证票据", SubjectUserName, SubjectDomainName, log.WinLog.ComputerName)
		form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", "", log.WinLog.ComputerName)
		return detect_plugins.NewPluginAlarm("high", desc, "LateralMovenment", "", log, d, *form_data)
	}

	return nil
}
