/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2021-09-08 10:40:38
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-02-10 12:48:34
 */
package system_plugin

import (
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"

	"fmt"
	"iatp/tools"
)

func init() {
	detect_plugins.RegisterPlugin(4765, NewSIDHistory())
	detect_plugins.RegisterPlugin(4766, NewSIDHistory())
}

type SIDHistory struct {
	*detect_plugins.SystemPlugin
}

func NewSIDHistory() *SIDHistory {
	return &SIDHistory{
		&detect_plugins.SystemPlugin{
			PluginName:    "SID History",
			PluginDesc:    "Sid History 权限维持",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (s *SIDHistory) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	var success bool

	if log.WinLog.EventID == 4765 {
		success = true
	} else {
		success = false
	}

	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
	TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
	TargetDomainName := tools.Interface2String(log.WinLog.EventData["TargetDomainName"])

	desc := fmt.Sprintf("发现 %s(%s) 账号 修改了%s(%s)账户的SIDHistory属性,修改结果:%v", SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName, success)

	form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", TargetUserName, log.WinLog.ComputerName)
	return detect_plugins.NewPluginAlarm("high", desc, "Persistence", "", log, s, *form_data)

}
