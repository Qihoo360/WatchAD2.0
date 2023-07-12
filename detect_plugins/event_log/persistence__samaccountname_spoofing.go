/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2022-02-09 18:16:54
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-02-10 09:33:34
 */
package system_plugin

import (
	"fmt"
	"iatp/common/domain"
	"iatp/common/logger"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/tools"
	"strings"

	"github.com/sirupsen/logrus"
)

/* samAccountName 欺骗攻击

可以使普通用户提权到管理员权限
*/

func init() {
	detect_plugins.RegisterPlugin(4742, NewSamAccountNameSpoofing())
}

type SamAccountNameSpoofing struct {
	*detect_plugins.SystemPlugin
}

func NewSamAccountNameSpoofing() *SamAccountNameSpoofing {
	return &SamAccountNameSpoofing{
		&detect_plugins.SystemPlugin{
			PluginName:    "samAccountName Spoofing",
			PluginDesc:    "samAccountName 欺骗攻击",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (s *SamAccountNameSpoofing) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	SamAccountName := tools.Interface2String(log.WinLog.EventData["SamAccountName"])
	TargetDomainName := tools.Interface2String(log.WinLog.EventData["TargetDomainName"])
	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])

	if SamAccountName == "-" || SamAccountName == "||" {
		return nil
	}

	d, err := domain.NewDomain(TargetDomainName)
	if err != nil {
		logger.IatpLogger.WithFields(logrus.Fields{
			"error": err,
			"fields": map[string]string{
				"TargetDomainName": TargetDomainName,
			},
			"event": event,
		}).Errorln("加载域对象失败")
	}

	for _, contorl := range d.GetDomainControls() {
		if strings.EqualFold(SamAccountName, contorl) {
			desc := fmt.Sprintf(`可疑用户利用%s权限, 将 %s(%s) 账户的samAccountName属性重置为 %s, 可疑的samAccountName欺骗攻击`, SubjectUserName, TargetUserName, TargetDomainName, SamAccountName)
			form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", SamAccountName, "-")
			return detect_plugins.NewPluginAlarm("high", desc, "Persistence", "", log, s, *form_data)
		} else {
			desc := fmt.Sprintf(`可疑用户利用%s权限, 将 %s(%s) 账户的samAccountName属性重置为 %s`, SubjectUserName, TargetUserName, TargetDomainName, SamAccountName)
			form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", SamAccountName, "-")
			return detect_plugins.NewPluginAlarm("low", desc, "Persistence", "", log, s, *form_data)
		}
	}

	return nil
}
