/*
 * @Descripttion: 
 * @version: 
 * @Author: daemon_zero
 * @Date: 2022-01-01 08:58:23
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-02-10 12:48:29
 */
package system_plugin

import (
	"fmt"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/tools"
	"strings"
)

/*
影子票证检测
*/

func init() {
	detect_plugins.RegisterPlugin(5136, NewShadowCredentials())
}

type ShadowCredentials struct {
	*detect_plugins.SystemPlugin
}

func NewShadowCredentials() *ShadowCredentials {
	return &ShadowCredentials{
		&detect_plugins.SystemPlugin{
			PluginName:    "Shadow Credentials",
			PluginDesc:    "影子票证",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (s *ShadowCredentials) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	AttributeLDAPDisplayName := tools.Interface2String(log.WinLog.EventData["AttributeLDAPDisplayName"])
	if AttributeLDAPDisplayName != "msDS-KeyCredentialLink" {
		return nil
	}

	DSType := tools.Interface2String(log.WinLog.EventData["DSType"])
	if DSType != "%%14676" {
		return nil
	}

	ObjectDN := tools.Interface2String(log.WinLog.EventData["ObjectDN"])
	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
	AttributeValue := tools.Interface2String(log.WinLog.EventData["AttributeValue"])

	if strings.HasPrefix(AttributeValue, "B:854:") {
		victim := strings.TrimPrefix(strings.Split(ObjectDN, ",")[0], "CN=")
		desc := fmt.Sprintf("发现 %s(%s) 账号在 %s 上配置了msDS-KeyCredentialLink,存在持久化利用行为", SubjectUserName, SubjectDomainName, ObjectDN)
		form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", victim, log.WinLog.ComputerName)
		return detect_plugins.NewPluginAlarm("high", desc, "Persistence", "", log, s, *form_data)
	}

	return nil
}
