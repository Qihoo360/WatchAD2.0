/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2021-12-12 19:49:02
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-02-10 12:46:50
 */
package system_plugin

import (
	"fmt"
	"iatp/common/domain"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/tools"
	"strings"
)

/*
4720: 创建用户账户

该规则检测创建了和域控制器账户相类似的用户账户.用以发现 CVE-2021-42287、 CVE-2021-42278 利用
*/

func init() {
	detect_plugins.RegisterPlugin(4720, NewSimilarDcUser())
	detect_plugins.RegisterPlugin(4738, NewSimilarDcUser())
}

type SimilarDcUser struct {
	*detect_plugins.SystemPlugin
}

func NewSimilarDcUser() *SimilarDcUser {
	return &SimilarDcUser{
		&detect_plugins.SystemPlugin{
			PluginName:    "Similar Dc User",
			PluginDesc:    "创建类似DC的用户账户",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (s *SimilarDcUser) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	// 更改用户属性
	if log.WinLog.EventID == 4738 {
		samAccountName := tools.Interface2String(log.WinLog.EventData["SamAccountName"])
		targetDomainName := tools.Interface2String(log.WinLog.EventData["TargetDomainName"])

		if s.detectAbnormalAccount(targetDomainName, samAccountName) {
			subjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
			subjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
			targetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
			desc := fmt.Sprintf("异常用户 %s(%s) 将 %s(%s) 的 SamAccountName 修改为类似DC的账户 %s,可能进一步提权以获取DC权限", subjectUserName, subjectDomainName, targetUserName, targetDomainName, samAccountName)
			form_data := detect_plugins.CreateAlarmTuples(subjectUserName, "-", samAccountName, fmt.Sprintf("%s$", samAccountName))
			return detect_plugins.NewPluginAlarm("high", desc, "activities", "", log, s, *form_data)
		}
	} else if log.WinLog.EventID == 4720 {
		targetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
		targetDomainName := tools.Interface2String(log.WinLog.EventData["TargetDomainName"])

		if s.detectAbnormalAccount(targetDomainName, targetUserName) {
			subjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
			subjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
			targetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
			desc := fmt.Sprintf("异常用户 %s(%s) 创建一个类似DC的账户 %s(%s),可能进一步提权以获取DC权限", subjectUserName, subjectDomainName, targetUserName, targetDomainName)
			form_data := detect_plugins.CreateAlarmTuples(subjectUserName, "-", targetUserName, fmt.Sprintf("%s$", targetUserName))
			return detect_plugins.NewPluginAlarm("high", desc, "activities", "", log, s, *form_data)
		}
	}
	return nil
}

func (s *SimilarDcUser) detectAbnormalAccount(DSName string, accountName string) bool {
	d, err := domain.NewDomain(DSName)
	if err != nil {
		return false
	}

	for _, dc := range d.DomainControls {
		if strings.EqualFold(accountName, dc) {
			return true
		}
	}

	return false
}
