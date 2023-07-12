/*
 * @Descripttion: 基于系统日志的ZeroLogon攻击检测
 * @version: 1.0.0
 * @Author: daemon_zero
 * @Date: 2022-02-10 15:10:11
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-02-14 10:14:28
 */

package system_plugin

import (
	"fmt"
	"iatp/common/domain"
	"iatp/common/logger"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	"iatp/tools"
	"net"
	"strings"

	"github.com/hirochachacha/go-smb2"
	"github.com/sirupsen/logrus"
)

func init() {
	detect_plugins.RegisterPlugin(4742, NewZeroLogon())
}

type ZeroLogon struct {
	*detect_plugins.SystemPlugin
}

func NewZeroLogon() *ZeroLogon {
	return &ZeroLogon{
		&detect_plugins.SystemPlugin{
			PluginName:    "ZeroLogon",
			PluginDesc:    "ZeroLogon 提权攻击",
			PluginVersion: "v1.0.0",
			PluginAuthor:  "iatp@iatp.com",
		},
	}
}

func (s *ZeroLogon) Detect(event interface{}) *detect_plugins.PluginAlarm {
	log := event.(decoder.SystemEvent)

	SubjectUserName := tools.Interface2String(log.WinLog.EventData["SubjectUserName"])
	TargetUserName := tools.Interface2String(log.WinLog.EventData["TargetUserName"])
	SubjectDomainName := tools.Interface2String(log.WinLog.EventData["SubjectDomainName"])
	TargetDomainName := tools.Interface2String(log.WinLog.EventData["TargetDomainName"])

	if !(SubjectDomainName == "NT AUTHORITY" && SubjectUserName == "ANONYMOUS LOGON") {
		return nil
	}

	if TargetUserName == "" {
		return nil
	}

	// 查找目标用户是域控账户的情况
	d, err := domain.NewDomain(TargetDomainName)
	if err != nil {
		logger.IatpLogger.WithFields(logrus.Fields{
			"error": err,
			"fields": map[string]string{
				"TargetDomainName": TargetDomainName,
			},
			"event": event,
		}).Errorln("加载域对象失败")
	}

	for _, contorl := range d.DomainControls {
		if strings.HasPrefix(TargetUserName, contorl) {
			// 判断域控密码是否为空密码
			if s.checkNoPass(contorl, d.DomainName) {
				desc := fmt.Sprintf(`域控制器 %s(%s) 的密码被重置为空密码, 可疑的ZeroLogon提权攻击`, TargetUserName, TargetDomainName)
				form_data := detect_plugins.CreateAlarmTuples("-", "-", TargetUserName, fmt.Sprintf("%s.%s", contorl, d.DomainName))
				return detect_plugins.NewPluginAlarm("high", desc, "Escalation", "", log, s, *form_data)
			}
		}
	}
	return nil
}

func (s *ZeroLogon) checkNoPass(contorlName, domainName string) bool {
	addrs, err := net.LookupHost(fmt.Sprintf("%s.%s", contorlName, domainName))
	if err != nil {
		logger.IatpLogger.WithFields(
			logrus.Fields{
				"error":     err,
				"host_name": fmt.Sprintf("%s.%s", contorlName, domainName),
			},
		).Errorln("域名解析失败")

		return true
	}

	if len(addrs) == 0 {
		logger.IatpLogger.WithFields(
			logrus.Fields{
				"host_name": fmt.Sprintf("%s.%s", contorlName, domainName),
			},
		).Errorln("域名解析失败,解析不到IP地址")

		return true
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", addrs[0]))
	if err != nil {
		logger.IatpLogger.WithFields(
			logrus.Fields{
				"error": err,
				"addrs": addrs[0],
			},
		).Errorln("TCP连接建立解析失败")
	}
	defer conn.Close()

	//smb auth
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     fmt.Sprintf("%s$", contorlName),
			Password: "",
			Domain:   strings.ToUpper(strings.Split(domainName, ".")[0]),
		},
	}

	_, err = d.Dial(conn)
	if err != nil {
		return false
	} else {
		return true
	}
}
