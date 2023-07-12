package system_plugin

import (
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"fmt"
	"iatp/tools"
)

/*
1. 连接打印服务尝试
*/

func init() {
	detect_plugins.RegisterPlugin(5145, NewSpoolSample())
	detect_plugins.RegisterPlugin(5156, NewSpoolSample())
}

type SpoolSample struct {
	*detect_plugins.SystemPlugin
}

func NewSpoolSample() *SpoolSample {
	return &SpoolSample{
		&detect_plugins.SystemPlugin{
			PluginName:    "SpoolSample",
			PluginDesc:    "攻击打印服务",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (s *SpoolSample) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	if log.WinLog.EventID == 5145 {
		RelativeTargetName := tools.Interface2String(log.WinLog.EventData["RelativeTargetName"])

		if RelativeTargetName == "spoolss" {
			IpAddress := tools.Interface2String(log.WinLog.EventData["IpAddress"])
			SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
			SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
			HostName := log.WinLog.ComputerName

			desc := fmt.Sprintf("收到了来自于%s身份为%s(%s)的主动认证发起请求，该行为一般用于诱导域控发起NTLM认证，经恶意目标中继后提升权限",
				IpAddress, SubjectUserName, SubjectDomainName)

			form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, IpAddress, fmt.Sprintf("%s$", HostName), HostName)
			return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, s, *form_data)
		}
	} else if log.WinLog.EventID == 5156 {
		Application := tools.Interface2String(log.WinLog.EventData["Application"])

		// 忽略非spoolsv.exe发起的请求
		if !strings.HasSuffix(Application, "spoolsv.exe") && Application != "System" {
			return nil
		}

		// 过滤掉非出站连接
		if tools.Interface2String(log.WinLog.EventData["Direction"]) != "%%14593" {
			return nil
		}

		DestAddress := tools.Interface2String(log.WinLog.EventData["DestAddress"])

		if Application == "System" && tools.Interface2String(log.WinLog.EventData["DestPort"]) == "445" {
			// 判断之前是否具有spoolss的告警
			filter := bson.M{
				"plugin_meta.systemplugin.plugin_name": s.PluginName,
				"victim_workstation":                   log.WinLog.ComputerName,
				"raw.time_stamp": bson.M{
					"$gte": log.TimeStamp.Add(-5 * time.Second),
					"$lte": log.TimeStamp,
				},
			}
			alarms := detect_plugins.QueryAlarm(filter)
			if alarms != nil {
				desc := fmt.Sprintf("发现打印服务再收到请求后,本机主动向外部 %s 发送SMB请求,可能是打印服务提权利用(CVE-2021-34527)", DestAddress)

				form_data := detect_plugins.CreateAlarmTuples("-", DestAddress, log.WinLog.ComputerName, log.WinLog.ComputerName)
				return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, s, *form_data)
			}
		} else if strings.HasSuffix(Application, "spoolsv.exe") {
			// TODO: 可能需要优化
			desc := fmt.Sprintf("Spoolsv.exe主动向外部 %s 发送S请求,打印服务漏洞利用可能已经成功", DestAddress)
			form_data := detect_plugins.CreateAlarmTuples("-", DestAddress, log.WinLog.ComputerName, log.WinLog.ComputerName)
			return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, s, *form_data)
		}
	}
	return nil
}
