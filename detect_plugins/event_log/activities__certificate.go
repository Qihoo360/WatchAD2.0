package system_plugin

import (
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/setting"
	"iatp/tools"
	"net"
	"strings"

	"iatp/common/domain"
	domain_client "iatp/common/domain"
	"iatp/common/logger"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

/*
1. 检测用户申请证书活动
2. 检测用户使用证书进行身份验证活动
*/

func init() {
	detect_plugins.RegisterPlugin(4887, NewCertificateActive())
	detect_plugins.RegisterPlugin(4768, NewCertificateActive())
	detect_plugins.RegisterPlugin(4624, NewCertificateActive())
}

type CertificateActive struct {
	*detect_plugins.SystemPlugin
}

func NewCertificateActive() *CertificateActive {
	return &CertificateActive{
		&detect_plugins.SystemPlugin{
			PluginName:    "Certificate Active",
			PluginDesc:    "证书服务活动",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (active *CertificateActive) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	switch log.WinLog.EventID {
	case 4887:
		Requester := tools.Interface2String(log.WinLog.EventData["Requester"])
		Attributes := tools.Interface2String(log.WinLog.EventData["Attributes"])

		format := strings.Split(Requester, "\\")

		if active.whiteAccount(format[1], format[0], "", nil) {
			return nil
		}

		level, desc := active.check_ask_for_certificate(format, Attributes)
		form_data := detect_plugins.CreateAlarmTuples("-", active.exportClient(Attributes), format[1], "-")
		return detect_plugins.NewPluginAlarm(level, desc, "activities", "", log, active, *form_data)
	case 4768:
		CertThumbprint := tools.Interface2String(log.WinLog.EventData["CertThumbprint"])

		if CertThumbprint == "" || CertThumbprint == "-" {
			return nil
		}

		TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
		TargetDomainName := tools.Interface2String(log.WinLog.EventData["TargetDomainName"])
		IpAddress := tools.Interface2String(log.WinLog.EventData["IpAddress"])

		IpAddress = strings.TrimPrefix(IpAddress, "::ffff:")

		if active.whiteAccount(TargetUserName, TargetDomainName, IpAddress, tools.CheckIPSegment) {
			return nil
		}

		level, desc := active.check_kerberos_auth(TargetUserName, TargetDomainName)
		form_data := detect_plugins.CreateAlarmTuples("-", IpAddress, TargetUserName, "-")
		return detect_plugins.NewPluginAlarm(level, desc, "activities", "", log, active, *form_data)
	case 4624:
		LogonProcessName := tools.Interface2String(log.WinLog.EventData["LogonProcessName"])
		WorkstationName := tools.Interface2String(log.WinLog.EventData["WorkstationName"])
		IpAddress := tools.Interface2String(log.WinLog.EventData["IpAddress"])
		TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
		TargetDomainName := tools.Interface2String(log.WinLog.EventData["TargetDomainName"])

		if LogonProcessName != "Schannel" {
			return nil
		}

		if active.whiteAccount(TargetUserName, TargetDomainName, strings.TrimPrefix(IpAddress, "::ffff:"), tools.CheckIPSegment) {
			return nil
		}

		level, desc := active.check_schannel_auth(TargetUserName, TargetDomainName)
		form_data := detect_plugins.CreateAlarmTuples("-", WorkstationName, TargetUserName, "-")
		return detect_plugins.NewPluginAlarm(level, desc, "activities", "", log, active, *form_data)
	}

	return nil
}

func (active *CertificateActive) check_schannel_auth(user string, domain_name string) (level string, desc string) {
	d, err := domain.NewDomain(domain_name)
	if err == nil {
		if d.IsHighRiskAccount(user) {
			desc = "高风险账户通过Schannel使用证书进行身份验证"
			return "high", desc
		}
	} else {
		logger.IatpLogger.WithFields(logrus.Fields{
			"error": err.Error(),
			"fields": map[string]string{
				"DSName": domain_name,
			},
		}).Errorln("create domain object error")
	}

	desc = "普通账户通过Schannel使用证书进行身份验证"
	return "low", desc
}

func (active *CertificateActive) check_ask_for_certificate(user_format []string, Attributes string) (level string, desc string) {
	d, err := domain.NewDomain(user_format[0])
	if err == nil {
		if d.IsHighRiskAccount(user_format[1]) {
			desc = "高风险账户成功申请证书,注意证书使用范围,可能存在持久化或证书盗用的问题"
			return "high", desc
		}
	} else {
		logger.IatpLogger.WithFields(logrus.Fields{
			"error": err.Error(),
			"fields": map[string]string{
				"DSName": user_format[0],
			},
		}).Errorln("create domain object error")
	}

	desc = "普通账户成功申请证书,注意证书使用范围,可能存在持久化或证书盗用的问题"
	return "low", desc
}

func (active *CertificateActive) check_kerberos_auth(user string, user_domain string) (level string, desc string) {
	d, err := domain.NewDomain(user_domain)
	if err == nil {
		if d.IsHighRiskAccount(user) {
			desc = "高风险账户使用证书进行进行身份验证"
			return "high", desc
		}
	} else {
		logger.IatpLogger.WithFields(logrus.Fields{
			"error": err.Error(),
			"fields": map[string]string{
				"DSName": user_domain,
			},
		}).Errorln("create domain object error")
	}

	desc = "普通证书使用证书进行身份验证"
	return "low", desc
}

func (active *CertificateActive) exportClient(attributes string) string {
	attribute := strings.Split(attributes, "\n")
	for _, v := range attribute {
		v = strings.Trim(v, "\t")
		if strings.HasPrefix(v, "rmd:") {
			return strings.TrimPrefix(v, "rmd:")
		}
	}

	return "-"
}

// 检查加白账户
func (active *CertificateActive) whiteAccount(user string, domain string, target_ip string, ip_segment_check func(ip_segment string, target_ip net.IP) bool) bool {
	certificate_activite := setting.IatpSetting.ReadSet("certificate_activite")

	m := certificate_activite.(primitive.D).Map()
	if _, ok := m[domain_client.FormatNetBiosDomain(domain)]; ok {
		for _, u := range m[domain_client.FormatNetBiosDomain(domain)].(primitive.A) {
			if _, ok := u.(primitive.D).Map()[user]; ok {
				if ip_segment_check == nil {
					return true
				}
				return ip_segment_check(u.(primitive.D).Map()[user].(string), net.ParseIP(target_ip))
			}
		}
	}
	return false
}
