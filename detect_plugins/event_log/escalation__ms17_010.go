package system_plugin

import (
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/setting"

	"fmt"
	"iatp/tools"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

/*
使用工具 https://github.com/apkjet/TrustlookWannaCryToolkit 扫描时，会触发该规则
使用原版exp 只触发 5140，且 SubjectLogonId 为一个不存在的值（0x后接5位随机数），即没有任何登录事件与之关联
*/

func init() {
	detect_plugins.RegisterPlugin(5140, NewMS17010())
}

type MS17010 struct {
	*detect_plugins.SystemPlugin
}

func NewMS17010() *MS17010 {
	return &MS17010{
		&detect_plugins.SystemPlugin{
			PluginName:    "MS17-010",
			PluginDesc:    "MS17-010",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (m *MS17010) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	if SubjectUserName != "ANONYMOUS LOGON" {
		return nil
	}

	ShareName := tools.Interface2String(log.WinLog.EventData["ShareName"])
	if ShareName != "\\\\*\\IPC$" {
		return nil
	}

	SubjectLogonId := tools.Interface2String(log.WinLog.EventData["SubjectLogonId"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
	HostName := log.WinLog.ComputerName
	Time := log.TimeStamp

	// 查询 4624 日志，查看是否存在SubjectLogonId

	if search(SubjectLogonId, Time, HostName) {
		desc := fmt.Sprintf("发现%s(%s)账户向%s服务器尝试利用MS17-010",
			SubjectUserName, SubjectDomainName, HostName)

		form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, tools.Interface2String(log.WinLog.EventData["IpAddress"]), "-", HostName)
		return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, m, *form_data)
	}
	return nil
}

func search(logonID string, timestamp time.Time, host string) bool {
	filter := bson.M{"event_type": "user_logon", "where": host, "logon_id": logonID, "when": bson.M{"$gt": timestamp.Add(-time.Hour * 2), "$lt": timestamp}}
	var result interface{}
	if err := setting.CacheMongo.FindOne(filter).Decode(result); err == nil {
		return false
	}
	return true
}
