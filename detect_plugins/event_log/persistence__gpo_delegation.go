package system_plugin

import (
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"

	"fmt"
	"iatp/tools"
	"strings"
)

var (
	sids = make([]string, 0)
)

func init() {
	detect_plugins.RegisterPlugin(5136, NewGPODelegation())
}

type GPODelegation struct {
	*detect_plugins.SystemPlugin
}

func NewGPODelegation() *GPODelegation {
	return &GPODelegation{
		&detect_plugins.SystemPlugin{
			PluginName:    "GPO DELEGATION",
			PluginDesc:    "GPO 权限委派",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (d *GPODelegation) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	ObjectClass := tools.Interface2String(log.WinLog.EventData["ObjectClass"])

	if ObjectClass != "groupPolicyContainer" {
		return nil
	}

	AttributeLDAPDisplayName := tools.Interface2String(log.WinLog.EventData["AttributeLDAPDisplayName"])
	if AttributeLDAPDisplayName != "nTSecurityDescriptor" {
		return nil
	}

	AttributeValue := tools.Interface2String(log.WinLog.EventData["AttributeValue"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])

	sddl := tools.SddlEngine{}
	if err := sddl.Parse(AttributeValue); err != nil {
		fmt.Println(err.Error())
	}
	acl := sddl.Dacl

	var abnormalAce []map[string]string
	for _, ace := range acl.Aces {
		if result := d.CheckPrivileges(ace, SubjectDomainName); result != nil {
			abnormalAce = append(abnormalAce, result...)
		}
	}

	if len(abnormalAce) > 0 {
		sids = tools.RemoveDuplicateElement(sids)
		desc := fmt.Sprintf("发现 %s(%s) 账号 赋予某些账户 %s 对组策略的修改委派权限",
			SubjectUserName, SubjectDomainName, strings.Join(sids, ","))

		form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", strings.Join(sids, ","), log.WinLog.ComputerName)
		return detect_plugins.NewPluginAlarm("high", desc, "Persistence", "", log, d, *form_data)
	}
	return nil
}

func (d *GPODelegation) CheckPrivileges(ace tools.Ace, DSName string) []map[string]string {
	var result []map[string]string
	for _, right := range ace.AceRights {
		switch right {
		case "Generic All":
			fallthrough
		case "Generic Write":
			fallthrough
		case "Write DAC":
			fallthrough
		case "Self Write":
			fallthrough
		case "Write Property":
			fallthrough
		case "Write Owner":
			if strings.HasPrefix(ace.SidString, "S-1-5-21-") {
				ace.SidString = d.GetUserBySid(DSName, ace.SidString)
				result = append(result, map[string]string{right: ace.SidString})
			}
		}
	}
	return result
}
