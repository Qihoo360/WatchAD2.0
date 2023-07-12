package system_plugin

import (
	"iatp/common/logger"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"

	"fmt"
	"iatp/tools"
	"strings"

	"github.com/sirupsen/logrus"
)

/*
ACL 异常修改
1. 敏感权限修改：
	- [√]WriteAll 、、、
2. 敏感的对象：
	- [√]AdminSDHolder
	- [√]根域 - 可能赋予dcsync权限
3. 清除adminCount属性
4. 监控对象所有者的恶意更改
    - [√]检查用户所有者为非Domain Admins的账户
5. 监控组对象的ACL权限：
	- []需要针对特殊的组进行特殊判断
*/

func init() {
	detect_plugins.RegisterPlugin(5136, NewAsRepRoasting())

	WatchObjectClass = []string{"container", "domainDNS", "groupPolicyContainer", "user", "group"}
	DcSyncAce = []string{"DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All"}
	DefaultDcSyncUser = []string{"Domain Controllers", "Built-in Administrators", "ENTERPRISE_READONLY_DOMAIN_CONTROLLERS", "Enterprise Domain Controllers"}
	DefaultTrustedUser = []string{"Domain Administrators", "Local System", "Account Operators", "Enterprise Administrators", "Certificate Publishers", "Builtin Terminal Server License Servers", "Principal Self", "Built-in Administrators"}
	MonitorGroup = []string{"CN=Domain Admins,CN=Users"}
}

var (
	WatchObjectClass   []string
	DcSyncAce          []string
	DefaultDcSyncUser  []string
	DefaultTrustedUser []string
	MonitorGroup       []string
	Users              []string
)

var (
	abnormal = true
	normal   = false
)

type ACLModify struct {
	*detect_plugins.SystemPlugin
}

func NewACLModify() *ACLModify {
	return &ACLModify{
		&detect_plugins.SystemPlugin{
			PluginName:    "ACL Modify",
			PluginDesc:    "ACL 异常修改行为",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (am *ACLModify) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	ObjectClass := tools.Interface2String(log.WinLog.EventData["ObjectClass"])
	if !am.WhiteListCheck(WatchObjectClass, ObjectClass) {
		return nil
	}

	AttributeLDAPDisplayName := tools.Interface2String(log.WinLog.EventData["AttributeLDAPDisplayName"])
	if AttributeLDAPDisplayName != "nTSecurityDescriptor" {
		return nil
	}

	ObjectDN := tools.Interface2String(log.WinLog.EventData["ObjectDN"])
	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
	HostName := log.WinLog.ComputerName
	OperationType := tools.Interface2String(log.WinLog.EventData["OperationType"])

	var (
		abnormalAce []map[string]string
		desc        string
		level       string
	)

	if OperationType != "%%14674" {
		return nil
	}

	// AdminSDHolder 对象ACL修改
	if strings.HasPrefix(ObjectDN, "CN=AdminSDHolder,CN=System") {
		desc = fmt.Sprintf("发现%s(%s)账户在%s服务器上修改了AdminSDHolder对象的ACL",
			SubjectUserName, SubjectDomainName, HostName)

		//attacker_workstation = am.GetSourceWorkStation()
		form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", "-", HostName)
		return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, am, *form_data)
	}

	// 异常ACl权限赋予
	DSName := tools.Interface2String(log.WinLog.EventData["DSName"])
	AttributeValue := tools.Interface2String(log.WinLog.EventData["AttributeValue"])
	// 修改根域ACL情况
	// 1. 普通用户存在DCSync 权限 -> high
	// 2. 其余修改根域ACL情况 -> high
	if ObjectClass == "domainDNS" {
		status := am.CheckDomainScopeAcl(AttributeValue, DSName)
		if status {
			desc = fmt.Sprintf("发现%s(%s)账户在%s服务器上赋予了%s对象DCSync权限",
				SubjectUserName, SubjectDomainName, HostName, tools.RemoveDuplicateElement(Users))
		} else {
			desc = fmt.Sprintf("发现%s(%s)账户在%s服务器上更新了根域的ACL",
				SubjectUserName, SubjectDomainName, HostName)
		}
		//attacker_workstation = am.GetSourceWorkStation()
		form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", "-", HostName)
		return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, am, *form_data)
	}

	// 根据基线判断异常
	// 目前梳理出来的基线
	// 1. 更改密码 Self EveryOne
	// 2. 完全控制 Domain Admins / SYSTEM / Account Operators / Enterprise Admins
	// 3. Generic Write ⇧
	// 4. WriteDacl     ⇧
	// 5. Self On Group ⇧
	// 6. WriteProperty ⇧
	// 7. WriteOwner    ⇧
	sddl := tools.SddlEngine{}
	if err := sddl.Parse(AttributeValue); err != nil {
		// 异常处理需要记录
		logger.IatpLogger.WithFields(
			logrus.Fields{
				"error": err.Error(),
				"event": event,
				"fields": map[string]string{
					"AttributeValue": AttributeValue,
				},
			},
		).Errorln("SDDL 格式解析失败")
	} else {
		if ObjectClass == "group" && am.isMonitorGroup(ObjectDN) || ObjectClass == "user" {
			for _, ace := range sddl.Dacl.Aces {
				// 检查特殊权限
				if result := am.CheckSpecialPrivileges(ace, DSName); result != nil {
					abnormalAce = append(abnormalAce, result)
				}
				// 检查基本权限
				if result := am.CheckBasicPrivileges(ace, DSName); result != nil {
					abnormalAce = append(abnormalAce, result...)
				}
			}

			if len(abnormalAce) > 0 {
				desc = fmt.Sprintf("发现%s(%s)账户更新了%s账户的ACL,并存在异常的权限",
					SubjectUserName, SubjectDomainName, ObjectDN)
				level = "high"
			} else {
				//ACL用户对象所有者检查
				if sddl.Owner != "Domain Administrators" {
					desc = fmt.Sprintf("发现%s(%s)账户更新了%s账户的ACL,ACL所有者归属于%s账户",
						SubjectUserName, SubjectDomainName, ObjectDN, sddl.Owner)
					//attacker_workstation = am.GetSourceWorkStation()
					form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", "-", HostName)
					return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, am, *form_data)
				}

				desc = fmt.Sprintf("发现%s(%s)账户更新了%s账户的ACL",
					SubjectUserName, SubjectDomainName, ObjectDN)
				level = "information"
			}
			//attacker_workstation = am.GetSourceWorkStation()
			form_data := detect_plugins.CreateAlarmTuples(SubjectUserName, "-", "-", HostName)
			return detect_plugins.NewPluginAlarm(level, desc, "Escalation", "", log, am, *form_data)
		}
	}
	return nil
}

func (am *ACLModify) CheckSpecialPrivileges(ace tools.Ace, DSName string) map[string]string {
	switch ace.ObjectGuid {
	case "User-Change-Password":
		if ace.SidString != "Principal Self" && ace.SidString != "Everyone" {
			// 异常
			if strings.HasPrefix(ace.SidString, "S-1-5-21-") {
				ace.SidString = am.GetUserBySid(DSName, ace.SidString)
			}
			return map[string]string{"User-Change-Password": am.GetUserBySid(DSName, ace.SidString)}
		}
	}
	return nil
}

func (am *ACLModify) CheckBasicPrivileges(ace tools.Ace, DSName string) []map[string]string {
	var result []map[string]string = nil
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
			if !am.WhiteListCheck(DefaultTrustedUser, ace.SidString) {
				if strings.HasPrefix(ace.SidString, "S-1-5-21-") {
					ace.SidString = am.GetUserBySid(DSName, ace.SidString)
				}
				result = append(result, map[string]string{right: ace.SidString})
			}
		}
	}
	return result
}

func (am *ACLModify) CheckDomainScopeAcl(AttributeValue, DSName string) bool {
	sddl := tools.SddlEngine{}
	if err := sddl.Parse(AttributeValue); err != nil {
		// 异常处理需要记录
		logger.IatpLogger.WithFields(
			logrus.Fields{
				"error": err.Error(),
				"fields": map[string]string{
					"AttributeValue": AttributeValue,
				},
			},
		).Errorln("ACL 解析失败")
	} else {
		users := make([]string, 0, 5)
		status, sids := am.CheckDcSyncAcl(sddl.Dacl.Aces, DSName)

		if status {
			for _, sid := range sids {
				users = append(users, am.GetUserBySid(DSName, sid))
			}
			Users = append(Users, users...)
			return true
		}
	}
	return false
}

func (am *ACLModify) CheckDcSyncAcl(aces []tools.Ace, dsName string) (bool, []string) {
	abnormal_sids := make([]string, 0, 10)
	for _, ace := range aces {
		// S-1-5-21-<root domain>-498 一个通用组包含林中的所有只读域控制器
		if am.WhiteListCheck(DcSyncAce, ace.ObjectGuid) && !am.WhiteListCheck(DefaultDcSyncUser, ace.SidString) {
			abnormal_sids = append(abnormal_sids, ace.SidString)
		}
	}

	if len(abnormal_sids) > 0 {
		return true, abnormal_sids
	}
	return false, nil
}

//TODO: 代码需要优化
func (am *ACLModify) isMonitorGroup(dn string) bool {
	for _, v := range MonitorGroup {
		if strings.HasPrefix(dn, v) {
			return true
		}
	}
	return false
}

func (am *ACLModify) WhiteListCheck(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}
