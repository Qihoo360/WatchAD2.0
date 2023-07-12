package system_plugin

import (
	"fmt"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/tools"
	"strings"
)

/*
ESC1: 指定subjectAltName实现权限提升(4898-请求证书时所加载的模板)
ESC2:
*/

func init() {
	detect_plugins.RegisterPlugin(4898, NewADCertificate())
}

type ADCertificate struct {
	*detect_plugins.SystemPlugin
}

func NewADCertificate() *SpoolSample {
	return &SpoolSample{
		&detect_plugins.SystemPlugin{
			PluginName:    "ADCS-ESC",
			PluginDesc:    "滥用证书服务权限提升",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (c *ADCertificate) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	// 检测异常证书模板

	// msPKI-Certificate-Name-Flag 启用了 CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT &&
	// 1.3.6.1.5.5.7.3.2 客户端身份验证 和 1.3.6.1.4.1.311.20.2.2 智能卡登录
	TemplateContent := tools.Interface2String(log.WinLog.EventData["TemplateContent"])
	TemplateDSObjectFQDN := tools.Interface2String(log.WinLog.EventData["TemplateDSObjectFQDN"])

	if strings.Contains(TemplateContent, "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT") && (strings.Contains(TemplateContent, "1.3.6.1.5.5.7.3.2") || strings.Contains(TemplateContent, "1.3.6.1.5.2.3.4") || strings.Contains(TemplateContent, "1.3.6.1.4.1.311.20.2.2")) {
		desc := fmt.Sprintf("%s模板存在错误配置,可能导致用户伪造管理员身份进行提权", strings.TrimPrefix(strings.Split(TemplateDSObjectFQDN, ",")[0], "CN="))
		form_data := detect_plugins.CreateAlarmTuples("-", "-", "-", "-")
		return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, c, *form_data)
	}
	return nil
}
