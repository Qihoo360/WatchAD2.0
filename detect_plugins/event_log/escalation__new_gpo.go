package system_plugin

import (
	"iatp/common/domain"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"

	"fmt"
	"iatp/tools"
	"strings"
)

/*

 */

func init() {
	detect_plugins.RegisterPlugin(5137, NewCreateGPO())
}

type CreateGPO struct {
	*detect_plugins.SystemPlugin
}

func NewCreateGPO() *CreateGPO {
	return &CreateGPO{
		&detect_plugins.SystemPlugin{
			PluginName:    "NEW GPO",
			PluginDesc:    "新增GPO监控",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (n *CreateGPO) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	ObjectClass := tools.Interface2String(log.WinLog.EventData["ObjectClass"])
	if ObjectClass != "groupPolicyContainer" {
		return nil
	}

	ObjectDN := tools.Interface2String(log.WinLog.EventData["ObjectDN"])
	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
	DSName := tools.Interface2String(log.WinLog.EventData["DSName"])
	HostName := log.WinLog.ComputerName

	cn := strings.TrimLeft(strings.Split(ObjectDN, ",")[0], "CN=")
	if d, err := domain.NewDomain(DSName); err != nil {
		fmt.Printf("new_gpo plugin NewDomain error: %v", err)
	} else {
		gpo, err := d.GetDomainGPOByUUID(cn)
		if err != nil {
			fmt.Printf("new_gpo plugin GetDomainGPOByUUID error: %v", err)
		}
		desc := fmt.Sprintf("发现%s(%s)账户创建了新的GPO(%s)",
			SubjectUserName, SubjectDomainName, gpo.GPOUUid)

		form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", "-", HostName)
		return detect_plugins.NewPluginAlarm("medium", desc, "Escalation", "", log, n, *form_data)
	}

	return nil
}
