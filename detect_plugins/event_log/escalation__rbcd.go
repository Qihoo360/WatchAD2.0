/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2021-09-08 10:40:38
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-02-10 12:47:59
 */
package system_plugin

import (
	"fmt"
	"iatp/common/domain"
	ldap_tool "iatp/common/ldap"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/tools"
	"iatp/tools/sddl"
	"strings"
)

func init() {
	detect_plugins.RegisterPlugin(5136, NewRbcd())
}

type Rbcd struct {
	*detect_plugins.SystemPlugin
}

func NewRbcd() *Rbcd {
	return &Rbcd{
		&detect_plugins.SystemPlugin{
			PluginName:    "Resource Based Constraint Delegation",
			PluginDesc:    "基于资源的约束委派",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (r *Rbcd) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	DSType := tools.Interface2String(log.WinLog.EventData["DSType"])
	if DSType != "%%14676" {
		return nil
	}

	AttributeLDAPDisplayName := tools.Interface2String(log.WinLog.EventData["AttributeLDAPDisplayName"])
	if AttributeLDAPDisplayName != "msDS-AllowedToActOnBehalfOfOtherIdentity" {
		return nil
	}

	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
	ObjectDN := tools.Interface2String(log.WinLog.EventData["ObjectDN"])

	// 受害者
	victim := strings.TrimPrefix(strings.Split(ObjectDN, ",")[0], "CN=")

	var attacker []string = make([]string, 0)

	// 攻击者
	d, err := domain.NewDomain(SubjectDomainName)
	if err == nil {
		// 域的ldap client
		ldap_client := ldap_tool.NewLdap(d.DomainServer, d.UserName, d.PassWord, d.GetDomainScope(), d.SSL)

		// 对象的client
		object_client := ldap_tool.NewLdap(d.DomainServer, d.UserName, d.PassWord, ObjectDN, d.SSL)

		entrys := object_client.SearchEntryByCN(victim, []string{"msDS-AllowedToActOnBehalfOfOtherIdentity"}, nil)
		for _, v := range entrys {
			aces := sddl.NewSDDL().ReadBytes(v.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")).Dacl.Aces

			for _, ace := range aces {
				entry := ldap_client.SearchEntryBySid(ace.GetSid().String(), []string{"cn"}, nil)
				if len(entry) > 0 {
					attacker = append(attacker, entry[0].GetAttributeValue("cn"))
				} else {
					attacker = append(attacker, ace.GetSid().String())
				}
			}
		}
	}

	attackers := strings.Join(attacker, ",")
	desc := fmt.Sprintf(`%s 使用 %s(%s) 账户身份向 %s 设置了基于资源的约束委派, 这将导致攻击者拥有 %s 完全管理权限`, attackers, SubjectUserName, SubjectDomainName, victim, victim)
	form_data := detect_plugins.CreateAlarmTuples(attackers, attackers, SubjectUserName, victim)

	return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, r, *form_data)
}
