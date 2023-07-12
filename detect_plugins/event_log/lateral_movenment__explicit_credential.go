package system_plugin

import (
	"iatp/common/domain"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/setting"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"fmt"
	"iatp/tools"
	"strings"
)

/*
显示凭据远程登录检测
1. TargetInfo - 附加信息需要过滤掉TERMSRV开头（远程桌面登录）
2. 需要检测非管理员账户使用管理员凭据显示登录
3. 排除 TargetServerName 和 TargetInfo是localhost的情况
4. 需要检测ProcessName出现在不正常的目录
*/

func init() {
	detect_plugins.RegisterPlugin(4648, NewExplicitCredential())
}

type ExplicitCredential struct {
	*detect_plugins.SystemPlugin
}

func NewExplicitCredential() *ExplicitCredential {
	return &ExplicitCredential{
		&detect_plugins.SystemPlugin{
			PluginName:    "Explicit Credential",
			PluginDesc:    "异常的显示凭据登录行为",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (receiver *ExplicitCredential) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	TargetInfo := tools.Interface2String(log.WinLog.EventData["TargetInfo"])
	TargetServerName := tools.Interface2String(log.WinLog.EventData["TargetServerName"])

	if TargetInfo == "localhost" || TargetServerName == "localhost" {
		return nil
	}

	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
	TargetDomainName := tools.Interface2String(log.WinLog.EventData["TargetDomainName"])
	ProcessName := tools.Interface2String(log.WinLog.EventData["ProcessName"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])

	form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", TargetUserName, TargetServerName)

	var desc string
	var level string

	if strings.HasPrefix(TargetUserName, "HealthMailbox") {
		return nil
	}

	if receiver.checkWhite(ProcessName) {
		return nil
	}

	if SubjectUserName != TargetUserName {
		d, err := domain.NewDomain(TargetDomainName)
		if err == nil {
			if d.IsHighRiskAccount(TargetUserName) {
				level = "high"
			}
		}

		level = "medium"
		desc = fmt.Sprintf("发现%s(%s)使用%s(%s)账户的显示凭据，登录了%s服务", SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName, TargetInfo)
		return detect_plugins.NewPluginAlarm(level, desc, "LateralMovenment", "", log, receiver, *form_data)
	}

	if !strings.HasPrefix(strings.ToLower(ProcessName), "c:\\windows\\system32\\") &&
		!strings.HasPrefix(strings.ToLower(ProcessName), "c:\\program files\\") &&
		!strings.HasPrefix(strings.ToLower(ProcessName), "c:\\program files(x86)\\") {
		desc = fmt.Sprintf("发现异常进程%s(%s)通过显示凭据登录%s(%s)账户", ProcessName, TargetInfo, TargetUserName, TargetDomainName)
		return detect_plugins.NewPluginAlarm("medium", desc, "LateralMovenment", "", log, receiver, *form_data)
	}
	return nil
}

func (receiver *ExplicitCredential) checkWhite(ProcessName string) bool {
	white_process_set := setting.IatpSetting.ReadSet("explicit_credential_process")

	if white_process_set == nil {
		return false
	}

	for _, v := range white_process_set.(primitive.A) {
		if strings.EqualFold(v.(string), ProcessName) {
			return true
		}
	}

	return false
}
