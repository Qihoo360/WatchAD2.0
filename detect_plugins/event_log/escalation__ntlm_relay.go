package system_plugin

import (
	"iatp/common/domain"
	"iatp/common/logger"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/learn"
	"iatp/setting"
	"net"
	"strings"

	"fmt"
	"iatp/tools"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

/*
 检测方案:
 NTLM Relay 本质上还是中继用户到服务认证,
 1. 解析用户可以的认证来源
 2. 在服务器4624中判断认证用户是否来自可信的登录源
*/

/*
Update:
- 2021/07/19: 机器账户来源存在多个IP地址,办公网内IP环境为DHCP模式,非固定绑定模式
- 2021/07/19: 用户账户需要排除VPN段(10.254/10.247)
- 2021/07/20: 针对某些特殊用户需要设置白名单过滤
- 2021/07/23: 只检测高风险账户，新增高风险机器账户只能有一个来源
- 2021/08/11: 检测4625日志,关注异常中继失败的情况
*/

func init() {
	detect_plugins.RegisterPlugin(4624, NewNTLMRelay())
	detect_plugins.RegisterPlugin(4625, NewNTLMRelay())
}

type NTLMRelay struct {
	*detect_plugins.SystemPlugin
}

func NewNTLMRelay() *NTLMRelay {
	return &NTLMRelay{
		&detect_plugins.SystemPlugin{
			PluginName:    "NTLM Relay",
			PluginDesc:    "NTLM 中继检测",
			PluginVersion: "v2.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (nr *NTLMRelay) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
	TargetDomainName := tools.Interface2String(log.WinLog.EventData["TargetDomainName"])
	IpAddress := tools.Interface2String(log.WinLog.EventData["IpAddress"])
	WorkStationName := tools.Interface2String(log.WinLog.EventData["WorkstationName"])
	AuthenticationPackageName := tools.Interface2String(log.WinLog.EventData["AuthenticationPackageName"])
	HostName := log.WinLog.ComputerName

	if AuthenticationPackageName != "NTLM" {
		return nil
	}

	if TargetUserName == "ANONYMOUS LOGON" {
		return nil
	}

	// 排查掉IpAddress 为空的情况
	if IpAddress == "-" || IpAddress == "" {
		return nil
	}

	// 主要监控高风险账户中继
	d, err := domain.NewDomain(TargetDomainName)
	if err != nil {
		return nil
	}

	if !d.IsHighRiskAccount(TargetUserName) {
		return nil
	}

	var desc string
	// 高风险机器账户只能有一个来源 (2021/07/23)
	if strings.HasSuffix(TargetUserName, "$") && !nr.IsLogonWhite(TargetUserName, IpAddress, WorkStationName) {
		if log.WinLog.EventID == 4625 {
			desc = fmt.Sprintf("发现高风险机器账户%s(%s)从异常来源 %s 登录失败, 可能为失败的NTLM中继行为", TargetUserName, TargetDomainName, IpAddress)
		} else if log.WinLog.EventID == 4624 {
			desc = fmt.Sprintf("发现高风险机器账户%s(%s)从异常来源 %s 登录, 可能为NTLM中继行为", TargetUserName, TargetDomainName, IpAddress)
		}

		form_data := detect_plugins.CreateAlarmTuples("-", IpAddress, TargetUserName, HostName)
		return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, nr, *form_data)
	}

	// 非机器账户, 判断当前IP是否是在学习期内的通用账户
	if !strings.HasSuffix(TargetUserName, "$") && !nr.IsLogonWhite(TargetUserName, IpAddress, WorkStationName) {
		if log.WinLog.EventID == 4625 {
			desc = fmt.Sprintf("发现%s(%s)账户身份向 %s 发起认证请求失败, 可能为失败的NTLM中继行为", TargetUserName, TargetDomainName, HostName)
		} else if log.WinLog.EventID == 4624 {
			desc = fmt.Sprintf("发现%s(%s)账户身份被中继到%s", TargetUserName, TargetDomainName, HostName)
		}

		form_data := detect_plugins.CreateAlarmTuples("-", IpAddress, TargetUserName, HostName)
		return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, nr, *form_data)
	}

	return nil
}

// 检查用户是否在百名单内
func (nr *NTLMRelay) checkWhite(logon_user string, logon_ip string) bool {
	set := setting.IatpSetting.ReadSet("ntlm_relay_white_user_segment")

	for _, user := range set.(primitive.A) {
		if ip_segments, ok := user.(primitive.D).Map()[logon_user]; ok {
			for _, segment := range strings.Split(ip_segments.(string), ",") {
				if tools.CheckIPSegment(segment, net.ParseIP(logon_ip)) {
					return true
				}
			}

			return false
		}
	}

	return false
}

// 检查账户是否从可信来源登录
func (nr *NTLMRelay) IsLogonWhite(TargetUserName, IpAddress, WorkStationName string) bool {
	// 确认账户是否已经被设置在白名单内
	if nr.checkWhite(TargetUserName, IpAddress) {
		return true
	}

	// 判断账户是否在学习,以及是否学习结束
	logon := learn.NewLogon()
	logon.LogonUser = TargetUserName
	logon, err := logon.GetLearnObject()
	if err != nil {
		logger.IatpLogger.WithFields(logrus.Fields{
			"error": err,
			"fields": map[string]interface{}{
				"TargetUserName":  TargetUserName,
				"IpAddress":       IpAddress,
				"WorkStationName": WorkStationName,
			},
		})
		return true
	}

	// 当前用户未加入学习
	if logon == nil {
		return true
	}

	// 当前用户学习未完成
	if !logon.IsEndLearn() {
		return true
	}

	// 当前学习的内容为空
	if len(logon.LogonIpAddress) == 0 && len(logon.LogonHost) == 0 {
		return true
	}

	// 机器账户只能有一个登录来源,并且来源主机名和登录主机名不一致
	if strings.HasSuffix(TargetUserName, "$") && (len(logon.LogonHost) > 1 || !strings.HasPrefix(TargetUserName, WorkStationName) || !logon.IsInLearnHosts(WorkStationName) || !logon.IsInLearnIPs(IpAddress)) {
		return false
	} else if strings.HasSuffix(TargetUserName, "$") {
		return true
	}

	if !strings.HasSuffix(TargetUserName, "$") && !(logon.IsInLearnHosts(WorkStationName) || logon.IsInLearnIPs(IpAddress)) {
		return false
	} else if !strings.HasSuffix(TargetUserName, "$") {
		return true
	}

	return false
}
