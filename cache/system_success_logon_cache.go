package cache

import (
	"fmt"
	decoder "iatp/decoder/event"
	"iatp/tools"
	"time"
)

func init() {
	CacheEventMap[4624] = NewSuccessLogonCache()
	CacheEventMap[4647] = NewSuccessLogonCache()
}

type SuccessLogonCache struct {
	EventType   string    `bson:"event_type"`
	Who         string    `bson:"who"`
	When        time.Time `bson:"when"`
	Where       string    `bson:"where"`
	FromHost    string    `bson:"from_host"`
	FromAddress string    `bson:"from_address"`
	Type        string    `bson:"type"`
	LogonID     string    `bson:"logon_id"`
}

func NewSuccessLogonCache() *SuccessLogonCache {
	return &SuccessLogonCache{}
}

func (s *SuccessLogonCache) IsWriteCache(event interface{}) interface{} {
	system_event := event.(decoder.SystemEvent)
	s = NewSuccessLogonCache()

	if system_event.WinLog.EventID == 4647 {
		s.Who = tools.Interface2String(system_event.WinLog.EventData["TargetUserName"])
		s.When = system_event.TimeStamp
		s.Where = system_event.WinLog.ComputerName
		s.Type = "logoff"
		s.LogonID = tools.Interface2String(system_event.WinLog.EventData["TargetLogonId"])
		s.EventType = "user_logon"
	} else if system_event.WinLog.EventID == 4624 {
		// 过滤掉System用户
		if tools.Interface2String(system_event.WinLog.EventData["SubjectUserSid"]) == "S-1-5-18" {
			return nil
		}

		s.Who = tools.Interface2String(system_event.WinLog.EventData["TargetUserName"])
		s.When = system_event.TimeStamp
		s.Where = system_event.WinLog.ComputerName
		s.FromHost = tools.Interface2String(system_event.WinLog.EventData["WorkstationName"])
		s.FromAddress = tools.Interface2String(system_event.WinLog.EventData["IpAddress"])
		s.Type = s.LogonType(tools.Interface2String(system_event.WinLog.EventData["LogonType"]))
		s.LogonID = tools.Interface2String(system_event.WinLog.EventData["TargetLogonId"])
		s.EventType = "user_logon"
	}

	return s
}

func (s *SuccessLogonCache) LogonType(logontype string) string {
	switch logontype {
	case "0":
		return "System"
	case "2":
		return "Interactive"
	case "3":
		return "Network"
	case "4":
		return "Batch"
	case "5":
		return "Service"
	case "6":
		return "Unlock"
	case "7":
		return "NetworkCleartext"
	case "8":
		return "NewCredentials"
	case "9":
		return "RemoteInteractive"
	case "10":
		return "CachedInteractive"
	case "11":
		return "CachedRemoteInteractive"
	case "12":
		return "CachedUnlock"
	default:
		return fmt.Sprintf("%s - Unknow", logontype)
	}
}
