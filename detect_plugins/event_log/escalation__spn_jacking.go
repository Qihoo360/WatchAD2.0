/*
 * @Descripttion: SPN 劫持检测
 * @version:
 * @Author: daemon_zero
 * @Date: 2022-02-11 18:02:32
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-02-14 15:26:27
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

func init() {
	detect_plugins.RegisterPlugin(4742, NewSpnJacking())
}

type SpnJacking struct {
	*detect_plugins.SystemPlugin
}

func NewSpnJacking() *SpnJacking {
	return &SpnJacking{
		&detect_plugins.SystemPlugin{
			PluginName:    "SPN Jacking",
			PluginDesc:    "SPN 劫持",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (s *SpnJacking) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
	TargetDomainName := tools.Interface2String(log.WinLog.EventData["TargetDomainName"])
	ServicePrincipalNames := tools.Interface2String(log.WinLog.EventData["ServicePrincipalNames"])

	if !strings.HasSuffix(TargetUserName, "$") {
		return nil
	}

	if ServicePrincipalNames == "" || ServicePrincipalNames == "-" {
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

	hostname := strings.ToLower(fmt.Sprintf("%s.%s", strings.TrimRight(TargetUserName, "$"), d.DomainName))

	SPNs := strings.Split(ServicePrincipalNames, "\n\t\t")
	for _, spn := range SPNs {
		// logger.IatpLogger.WithFields(
		// 	logrus.Fields{
		// 		"spn":               spn,
		// 		"contains_hostname": strings.Contains(strings.ToLower(spn), hostname),
		// 		"contains":          strings.Contains(strings.ToLower(spn), strings.ToLower(strings.TrimRight(TargetUserName, "$"))),
		// 		"host_name":         hostname,
		// 	},
		// ).Infoln("打点标记")
		if spn != "" && !(strings.Contains(strings.ToLower(spn), hostname) || strings.Contains(strings.ToLower(spn), strings.ToLower(strings.TrimRight(TargetUserName, "$")))) {
			desc := fmt.Sprintf(`检测到 %s(%s) 用户向 %s(%s) 添加了异常的SPN值，疑似SPN劫持攻击`, SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName)
			form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", TargetUserName, hostname)
			return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, s, *form_data)
		}
	}

	return nil
}
