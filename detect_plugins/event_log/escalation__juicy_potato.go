/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2021-11-10 12:33:22
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-01-24 14:05:06
 */
package system_plugin

import (
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/setting"

	"fmt"
	"iatp/tools"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

/*
烂土豆提权

TODO: 2021/8/20 svchost.exe进程触发误报, 事件ID:611f5422876ecb07ac086578
*/

func init() {
	detect_plugins.RegisterPlugin(5156, NewJuicyPotato())
}

type JuicyPotato struct {
	*detect_plugins.SystemPlugin
}

func NewJuicyPotato() *JuicyPotato {
	return &JuicyPotato{
		&detect_plugins.SystemPlugin{
			PluginName:    "JuicyPotato",
			PluginDesc:    "烂土豆提权",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (jp *JuicyPotato) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	SourceAddress := tools.Interface2String(log.WinLog.EventData["SourceAddress"])
	DestAddress := tools.Interface2String(log.WinLog.EventData["DestAddress"])
	DestPort := tools.Interface2String(log.WinLog.EventData["DestPort"])

	// 特征1: 源==目的==127.0.0.1 && DestPort 135 (RPC)
	// 特征2: 同一父进程会提权方式启动子进程(判断提权成功)
	if SourceAddress == DestAddress && SourceAddress == "127.0.0.1" && DestPort == "135" {
		Application := tools.Interface2String(log.WinLog.EventData["Application"])
		HostName := log.WinLog.ComputerName
		Time := log.TimeStamp

		// 误报
		if Application == "\\device\\harddiskvolume2\\windows\\system32\\svchost.exe" {
			return nil
		}

		application_exe := strings.Split(Application, "\\")[len(strings.Split(Application, "\\"))-1]
		filter := bson.M{"event_type": "process_create",
			"when":                 bson.M{"$gte": Time.Add(-time.Second * 5), "$lte": Time},
			"host_name":            HostName,
			"subject_user_sid":     "S-1-5-18",
			"token_elevation_type": "%%1936",
			"parent_process_name":  bson.M{"$regex": primitive.Regex{Pattern: fmt.Sprintf("%s$", application_exe), Options: "i"}}}

		var result interface{}

		waiting_time := time.Now().Add(2 * time.Minute)
		now := time.Now()
		for now.Before(waiting_time) {
			if err := setting.CacheMongo.FindOne(filter).Decode(&result); err == nil {
				desc := fmt.Sprintf("在%s主机上发现可疑进程 %s 连接到RPC端口的异常行为,疑似烂土豆提权",
					HostName, Application)

				form_data := detect_plugins.CreateAlarmTuples("-", "-", "-", HostName)
				return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, jp, *form_data)
			}
			// 5秒等待
			time.Sleep(5 * time.Second)
			now = time.Now()
		}
	}
	return nil
}
