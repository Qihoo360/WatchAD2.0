/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2021-09-08 10:40:38
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-02-10 12:48:38
 */
package system_plugin

import (
	"fmt"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/tools"
)

func init() {
	detect_plugins.RegisterPlugin(4771, NewSkeletonKey())
}

type SkeletonKey struct {
	*detect_plugins.SystemPlugin
}

func NewSkeletonKey() *SkeletonKey {
	return &SkeletonKey{
		&detect_plugins.SystemPlugin{
			PluginName:    "Skeleton Key",
			PluginDesc:    "万能密钥",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (s *SkeletonKey) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	TicketOptions := tools.Interface2String(log.WinLog.EventData["TicketOptions"])
	PreAuthType := tools.Interface2String(log.WinLog.EventData["PreAuthType"])
	Status := tools.Interface2String(log.WinLog.EventData["Status"])

	if TicketOptions != "0x50802000" && TicketOptions != "0x0" {
		return nil
	}

	if PreAuthType != "0" {
		return nil
	}

	if Status != "0xe" {
		return nil
	}

	IpAddress := tools.Interface2String(log.WinLog.EventData["IpAddress"])
	desc := fmt.Sprintf("通过来自于 %s 发起的主动扫描，在域控 %s 上发现了万能钥匙后门", IpAddress, log.WinLog.ComputerName)

	form_data := detect_plugins.CreateAlarmTuples("-", "-", "ALL Domain User", log.WinLog.ComputerName)
	return detect_plugins.NewPluginAlarm("high", desc, "Persistence", "", log, s, *form_data)
}
