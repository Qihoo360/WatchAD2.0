/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2021-09-08 10:40:38
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-02-10 12:46:44
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

/*
记录机器账户创建事件活动
2021-07-23: 新增检测机器账户创建机器账户(可能是中继导致的异常行为)
*/

func init() {
	detect_plugins.RegisterPlugin(4741, NewCreateMachineUser())
}

type CreateMachineUser struct {
	*detect_plugins.SystemPlugin
}

func NewCreateMachineUser() *CreateMachineUser {
	return &CreateMachineUser{
		&detect_plugins.SystemPlugin{
			PluginName:    "Create Machine User",
			PluginDesc:    "创建机器账户事件活动",
			PluginVersion: "v1.1.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (c *CreateMachineUser) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])

	d, err := domain.NewDomain(SubjectDomainName)
	if err != nil {
		logger.IatpLogger.WithFields(
			logrus.Fields{
				"error": err.Error(),
				"event": event,
				"fields": map[string]string{
					"DSName": SubjectDomainName,
				},
			},
		).Errorln("create domain object error")
	}

	TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
	TargetDomainName := tools.Interface2String(log.WinLog.EventData["TargetDomainName"])

	if d.IsJoinDomainAdminUser(SubjectUserName) {
		return nil
	}

	if strings.HasSuffix(SubjectUserName, "$") {
		desc := fmt.Sprintf(`异常机器账户 %s(%s) 创建了 %s(%s) 机器账户`, SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName)
		form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", TargetUserName, TargetUserName[:len(TargetUserName)-1])
		return detect_plugins.NewPluginAlarm("high", desc, "activities", "", log, c, *form_data)
	}

	// 正常事件记录
	desc := fmt.Sprintf(`%s(%s) 创建了 %s(%s) 机器账户`, SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName)
	form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", TargetUserName, TargetUserName[:len(TargetUserName)-1])
	return detect_plugins.NewPluginAlarm("information", desc, "activities", "", log, c, *form_data)
}
