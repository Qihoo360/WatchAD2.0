package learn

import (
	"fmt"
	decoder "iatp/decoder/event"
	"iatp/setting"
	"iatp/tools"
	"net"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

/*
登录行为学习
*/

type Logon struct {
	LogonHost      []string
	LogonIpAddress []string
	LogonUser      string
	LearnType      string
	LearnStart     time.Time
	LearnEnd       time.Time
}

func NewLogon() *Logon {
	return &Logon{
		LogonHost:      make([]string, 0, 5),
		LogonIpAddress: make([]string, 0, 5),
		LogonUser:      "",
		LearnType:      "logon",
		LearnStart:     time.Now().Local(),
		LearnEnd:       time.Now().Local().AddDate(0, 3, 0), // 3个月
	}
}

func (l *Logon) Learn(event interface{}) error {
	// 异常捕获
	system_event := event.(decoder.SystemEvent)

	if system_event.WinLog.EventData["AuthenticationPackageName"] == nil {
		return fmt.Errorf("Event AuthenticationPackageName field is nil")
	}

	AuthenticationPackageName := system_event.WinLog.EventData["AuthenticationPackageName"].(string)
	if AuthenticationPackageName != "NTLM" {
		return nil
	}

	// 异常捕获
	if system_event.WinLog.EventData["WorkstationName"] == nil {
		return fmt.Errorf("Event WorkstationName field is nil")
	}

	host := system_event.WinLog.EventData["WorkstationName"].(string)
	ip := system_event.WinLog.EventData["IpAddress"].(string)
	user := system_event.WinLog.EventData["TargetUserName"].(string)

	if user == "ANONYMOUS LOGON" {
		// 忽略匿名账户
		return nil
	}

	// 确认账户是否已经被设置在白名单内
	if l.checkWhite(user, ip) {
		return nil
	}

	var msg Logon
	if err := setting.LearnMongo.FindOne(bson.M{"learntype": "logon", "logonuser": user}).Decode(&msg); err != nil {
		// 该用户没有经过学习
		if err == mongo.ErrNilDocument || err == mongo.ErrNoDocuments {
			logon := NewLogon()
			if host != "-" && host != "" {
				logon.LogonHost = append(logon.LogonHost, host)
			}
			logon.LogonIpAddress = append(logon.LogonIpAddress, ip)
			logon.LogonUser = user
			setting.LearnMongo.InsertOne(logon)
		}
	} else {
		// 已经存在学习记录
		if !msg.IsInLearnHosts(host) && host != "-" && host != "" {
			msg.LogonHost = append(msg.LogonHost, host)
		}
		if !msg.IsInLearnIPs(ip) {
			msg.LogonIpAddress = append(msg.LogonIpAddress, ip)
		}
		setting.LearnMongo.UpdateOne(bson.M{"learntype": "logon", "logonuser": user}, bson.M{"$set": msg})
	}
	return nil
}

func (l *Logon) IsInLearnHosts(host string) bool {
	for _, v := range l.LogonHost {
		if v == host {
			return true
		}
	}
	return false
}

func (l *Logon) IsInLearnIPs(ip string) bool {
	for _, v := range l.LogonIpAddress {
		if v == ip {
			return true
		}
	}
	return false
}

func (l *Logon) IsEndLearn() bool {
	now := time.Now()
	return now.After(l.LearnEnd)
}

// 获取当前学习对象
func (l *Logon) GetLearnObject() (*Logon, error) {
	var result Logon
	if err := setting.LearnMongo.FindOne(bson.M{"learntype": "logon", "logonuser": l.LogonUser}).Decode(&result); err == nil {
		return &result, nil
	} else {
		if err == mongo.ErrNilDocument || err == mongo.ErrNoDocuments {
			return nil, nil
		} else {
			return nil, err
		}
	}
}

// 检查用户是否在百名单内
func (l *Logon) checkWhite(logon_user string, logon_ip string) bool {
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
