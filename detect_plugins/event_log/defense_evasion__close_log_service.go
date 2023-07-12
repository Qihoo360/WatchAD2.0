package system_plugin

import (
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"

	"fmt"
)

func init() {
	detect_plugins.RegisterPlugin(1100, NewCloseLogService())
}

type CloseLogService struct {
	*detect_plugins.SystemPlugin
}

func NewCloseLogService() *CloseLogService {
	return &CloseLogService{
		&detect_plugins.SystemPlugin{
			PluginName:    "Close Log Service",
			PluginDesc:    "关闭系统日志服务",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (c *CloseLogService) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	// TODO:
	// 需要进一步判断是否是系统重启的原因导致的日志服务关闭
	// 先有重启的日志(1074) -> 日志服务关闭
	desc := fmt.Sprintf("域控 %s 的安全事件日志服务被关闭", log.WinLog.ComputerName)
	form_data := detect_plugins.CreateAlarmTuples("-", "-", "-", log.WinLog.ComputerName)
	return detect_plugins.NewPluginAlarm("low", desc, "DefenseEvasion", "", log, c, *form_data)
}
