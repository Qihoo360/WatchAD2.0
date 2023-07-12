package system_plugin

import (
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"

	"fmt"
	"iatp/tools"
	"regexp"
	"strings"
)

/*
远程代码执行
*/

func init() {
	detect_plugins.RegisterPlugin(5145, NewRemoteCodeExec())
	detect_plugins.RegisterPlugin(5142, NewRemoteCodeExec())
}

type RemoteCodeExec struct {
	*detect_plugins.SystemPlugin
}

func NewRemoteCodeExec() *RemoteCodeExec {
	return &RemoteCodeExec{
		&detect_plugins.SystemPlugin{
			PluginName:    "Remote Code Execute",
			PluginDesc:    "远程命令执行",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (receiver *RemoteCodeExec) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	ID := log.WinLog.EventID
	ShareName := tools.Interface2String(log.WinLog.EventData["ShareName"])
	RelativeTargetName := tools.Interface2String(log.WinLog.EventData["RelativeTargetName"])
	IpAddress := tools.Interface2String(log.WinLog.EventData["IpAddress"])
	SubjectUserName := tools.Interface2String(log.WinLog.EventData["IpAddress"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
	HostName := log.WinLog.ComputerName

	var desc string

	if ID == 5145 {
		switch ShareName {
		case "\\\\*\\ADMIN$":
			if receiver.checkPsEsxc(RelativeTargetName) {
				desc = fmt.Sprintf("发现%s使用%s(%s)账户在%s服务器上使用PsExec工具远程执行命令", IpAddress, SubjectUserName, SubjectDomainName, HostName)
				break
			}
			if receiver.checkWmiExec(RelativeTargetName) {
				desc = fmt.Sprintf("发现%s使用%s(%s)账户在%s服务器上使用WmiExec工具远程执行命令", IpAddress, SubjectUserName, SubjectDomainName, HostName)
				break
			}
		case "\\\\*\\C$":
			if receiver.checkSMBExec(RelativeTargetName) {
				desc = fmt.Sprintf("发现%s使用%s(%s)账户在%s服务器上使用SmbExec工具远程执行命令", IpAddress, SubjectUserName, SubjectDomainName, HostName)
				break
			}
		}

		if desc != "" {
			form_data := detect_plugins.CreateAlarmTuples("-", IpAddress, SubjectUserName, HostName)
			return detect_plugins.NewPluginAlarm("high", desc, "LateralMovenment", "", log, receiver, *form_data)
		}
	} else if ID == 5142 {
		ShareLocalPath := tools.Interface2String(log.WinLog.EventData["ShareLocalPath"])
		if ShareName == `\\*\WMI_SHARE` && !strings.HasPrefix(strings.ToLower(ShareLocalPath), "c:\\system32") {
			desc = fmt.Sprintf("发现%s(%s)账户调用WMI创建异常网络共享对象", SubjectUserName, SubjectDomainName)
			form_data := detect_plugins.CreateAlarmTuples("-", "-", SubjectUserName, HostName)
			return detect_plugins.NewPluginAlarm("high", desc, "LateralMovenment", "", log, receiver, *form_data)
		}
	}
	return nil
}

func (receiver *RemoteCodeExec) checkPsEsxc(RelativeTargetName string) bool {
	return RelativeTargetName == "PSEXESVC.exe"
}

func (receiver *RemoteCodeExec) checkSMBExec(RelativeTargetName string) bool {
	return RelativeTargetName == "__output"
}

func (receiver RemoteCodeExec) checkWmiExec(RelativeTargetName string) bool {
	r, _ := regexp.Compile(`^__\d{1,}.\d{1,}$`)
	return r.MatchString(RelativeTargetName)
}
