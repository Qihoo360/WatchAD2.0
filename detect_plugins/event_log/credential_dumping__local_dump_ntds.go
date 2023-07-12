package system_plugin

import (
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"

	"fmt"
	"iatp/tools"
	"strings"
)

/*
Dump Ntds.dit 密码文件
event_id: 8222 创建影子副本
需要针对域控服务器做排除
*/

func init() {
	detect_plugins.RegisterPlugin(8222, NewDumpNtds())
}

type DumpNtds struct {
	*detect_plugins.SystemPlugin
}

func NewDumpNtds() *DumpNtds {
	return &DumpNtds{
		&detect_plugins.SystemPlugin{
			PluginName:    "Local Dump Ntds",
			PluginDesc:    "本地Dump Ntds文件利用",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (receiver *DumpNtds) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	for _, v := range log.Tags {
		if v == "iatp-dc" {
			goto start
		}
	}
	return nil
start:
	TargetUserName := tools.Interface2String(log.WinLog.EventData["param2"]) //创建进程用户名
	Image := tools.Interface2String(log.WinLog.EventData["param4"])          //进程映像名称
	ComputerName := tools.Interface2String(log.WinLog.EventData["param8"])

	form_data := detect_plugins.CreateAlarmTuples(TargetUserName, ComputerName, ComputerName, ComputerName)

	switch {
	case strings.HasSuffix(Image, "WmiPrvSE.exe"):
		fallthrough
	case strings.HasSuffix(Image, "ntdsutil.exe"):
		fallthrough
	case strings.HasSuffix(Image, "vssadmin.exe"):
		desc := fmt.Sprintf("发现%s调用卷影复制服务", TargetUserName)
		return detect_plugins.NewPluginAlarm("high", desc, "CredentialDumping", "", log, receiver, *form_data)
	case strings.HasSuffix(Image, "System32\\wbengine.exe"): // 系统备份进程
		fallthrough
	case strings.HasSuffix(Image, "Microsoft System Center\\DPM\\DPM\\bin\\msdpm.exe"): // dpm 备份系统进程
		fallthrough
	case strings.Contains(Image, "Veritas\\NetBackup\\bin"):
		fallthrough
	case strings.HasSuffix(Image, "Microsoft Data Protection Manager\\DPM\\bin\\DPMRA.exe"):
		return nil
	default:
		desc := fmt.Sprintf("发现%s调用卷影复制服务(未知进程)", TargetUserName)
		return detect_plugins.NewPluginAlarm("high", desc, "CredentialDumping", "", log, receiver, *form_data)
	}
}
