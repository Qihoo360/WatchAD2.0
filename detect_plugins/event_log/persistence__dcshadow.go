package system_plugin

import (
	"iatp/common/domain"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/tools"

	"fmt"
	"strings"
)

/*
4742:
	GC/DESKTOP-39GTP00.contoso.com/contoso.com
	E3514235-4B06-11D1-AB04-00C04FC2DCD2/da549357-0f5a-4b20-a03b-e31af36cac1d/contoso.com
5137:
	检测CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration相关的目录服务更改


审核修改了哪些内容:
周期性调用域内所有对象的msDS-ReplAttributeMetaData查看修改了哪些内容
*/

func init() {
	detect_plugins.RegisterPlugin(4742, NewDCShadow())
	detect_plugins.RegisterPlugin(5137, NewDCShadow())
}

type DCShadow struct {
	*detect_plugins.SystemPlugin
}

func NewDCShadow() *DCShadow {
	return &DCShadow{
		&detect_plugins.SystemPlugin{
			PluginName:    "DCShadow",
			PluginDesc:    "DCShadow 权限维持",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (d *DCShadow) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	EventID := log.WinLog.EventID

	HostName := log.WinLog.ComputerName
	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
	TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])

	if EventID == 4742 {
		ServicePrincipalNames := tools.Interface2String(log.WinLog.EventData["ServicePrincipalNames"])
		TargetDomainName := tools.Interface2String(log.WinLog.EventData["TargetDomainName"])

		alert := d.check_account_change(ServicePrincipalNames, HostName, TargetDomainName)

		if alert {
			desc := fmt.Sprintf("发现 %s(%s) 账号将机器账户 %s 注册为 %s 域的域控制器",
				SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName)

			form_data := detect_plugins.CreateAlarmTuples(TargetUserName, strings.TrimRight(TargetUserName, "$"), "-", HostName)
			return detect_plugins.NewPluginAlarm("high", desc, "Persistence", "", log, d, *form_data)
		}

	} else if EventID == 5137 {
		ObjectDN := tools.Interface2String(log.WinLog.EventData["ObjectDN"])
		DSName := tools.Interface2String(log.WinLog.EventData["DSName"])
		ObjectClass := tools.Interface2String(log.WinLog.EventData["ObjectClass"])

		if ObjectClass != "server" {
			return nil
		}

		alert := d.check_directory_object_created(ObjectDN, DSName, HostName)
		if alert {
			attack_account := strings.TrimLeft(strings.Split(ObjectDN, ",")[0], "CN=")
			desc := fmt.Sprintf("发现 %s(%s) 账号将机器账户 %s 注册为 %s 域的域控制器",
				SubjectUserName, SubjectDomainName, attack_account, DSName)

			form_data := detect_plugins.CreateAlarmTuples(TargetUserName, strings.TrimRight(TargetUserName, "$"), "-", HostName)
			return detect_plugins.NewPluginAlarm("high", desc, "Persistence", "", log, d, *form_data)
		}
	}

	return nil
}

// 检查账户更改
func (d *DCShadow) check_account_change(ServicePrincipalNames, HostName, TargetDomainName string) bool {
	gcTag := false
	drsTag := false

	SPNs := strings.Split(ServicePrincipalNames, "\n\t\t")
	for _, spn := range SPNs {
		if strings.HasPrefix(spn, "GC") {
			gcTag = true
		} else if strings.HasPrefix(spn, "E3514235-4B06-11D1-AB04-00C04FC2DCD2") {
			drsTag = true
		}
	}

	if gcTag && drsTag {
		//  检查可能的修改项
		// TODO: 待优化项： 设置一个准确的结束时间，目前设置为3分钟
		// time.Sleep(3 * time.Minute)
		// d.check_modify(HostName, TargetDomainName)

		// 如果该账户已经是域控制器账户则忽略告警
		domain, err := domain.NewDomain(TargetDomainName)
		if err != nil {
			fmt.Printf("域对象创建失败: %v", err)
			return false
		}

		for _, dcontrol := range domain.DomainControls {
			if strings.HasPrefix(HostName, dcontrol) {
				return false
			}
		}

		return true
	}

	return false
}

// 检查目录服务更改, 针对将计算机注册到域控目录下
func (d *DCShadow) check_directory_object_created(ObjectDN, DSName, HostName string) bool {
	domain, err := domain.NewDomain(DSName)
	if err != nil {
		fmt.Printf("dcshadow - %v\n", err)
		return false
	}
	object_suffix := fmt.Sprintf("CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,%s", domain.GetDomainScope())

	//  检查可能的修改项
	// TODO: 待优化项： 设置一个准确的结束时间，目前设置为3分钟
	// time.Sleep(3 * time.Minute)
	// d.check_modify(HostName, DSName)
	return strings.HasSuffix(ObjectDN, object_suffix)
}

// 检查dcshadow可能的更改项
// func (d *DCShadow) check_modify(HostName, DSName string) {

// 	domain, err := domain.NewDomain(DSName)
// 	if err != nil {
// 		fmt.Printf("域对象创建失败: %v", err)
// 	}

// 	addr, err := net.ResolveIPAddr("ip", fmt.Sprintf("%s.%s", HostName, domain.DomainName))
// 	if err != nil {
// 		return
// 	}

// 	domain_ldap := l.NewLdap(addr.String(), domain.UserName, domain.PassWord, domain.GetDomainScope(), domain.SSL)
// 	domain_ldap.PageSearchHandler("(objectclass=*)", []string{"dn", "msDS-ReplAttributeMetaData"}, 100, HostName, repl_meta_data_check)
// }

// func repl_meta_data_check(entry *ldap.Entry, control_server string) {
// 	different = make([]string, 0)

// 	repl_index := database.NewMgo("ata", "ata_replmetadata")
// 	var mongo_repl_meta_data meta_data.ReplMetaData

// 	FilterResult := repl_index.FindOne(bson.M{"dn": entry.DN, "control": control_server})
// 	repl_meta_data := meta_data.MetaData2Json(entry.GetAttributeValues("msDS-ReplAttributeMetaData"))
// 	sha := tools.GetSha1s(entry.GetAttributeValues("msDS-ReplAttributeMetaData"))

// 	if err := FilterResult.Decode(&mongo_repl_meta_data); err == nil {
// 		// 数据库中已存储, 比对异常
// 		if mongo_repl_meta_data.SHA != sha {
// 			var meta_data_result meta_data.MetaData
// 			for _, d := range repl_meta_data {
// 				if err := repl_index.FindOne(bson.M{"dn": entry.DN, "control": control_server, "meta_data": d}).Decode(&meta_data_result); err != nil {
// 					different = append(different, d.PSZAttributeName)
// 				}
// 			}
// 		}
// 	}
// }
