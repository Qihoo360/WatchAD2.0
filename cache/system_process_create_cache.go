package cache

import (
	decoder "iatp/decoder/event"
	"iatp/tools"
	"time"
)

func init() {
	CacheEventMap[4688] = NewSystemProcessCreateCache()
}

type SystemProcessCreateCache struct {
	EventType          string    `bson:"event_type"` // 事件类型
	HostName           string    `bson:"host_name"`
	SubjectUserSid     string    `bson:"subject_user_sid"`
	TokenElevationType string    `bson:"token_elevation_type"`
	ProcessName        string    `bson:"process_name"`
	ParentProcessName  string    `bson:"parent_process_name"`
	When               time.Time `bson:"time_stamp"`
}

func NewSystemProcessCreateCache() *SystemProcessCreateCache {
	return &SystemProcessCreateCache{}
}

func (s *SystemProcessCreateCache) IsWriteCache(event interface{}) interface{} {
	log := event.(decoder.SystemEvent)

	process_create := NewSystemProcessCreateCache()
	process_create.EventType = "process_create"
	process_create.HostName = log.WinLog.ComputerName
	process_create.SubjectUserSid = tools.Interface2String(log.WinLog.EventData["SubjectUserSid"])
	process_create.TokenElevationType = tools.Interface2String(log.WinLog.EventData["TokenElevationType"])
	process_create.ProcessName = tools.Interface2String(log.WinLog.EventData["NewProcessName"])
	process_create.ParentProcessName = tools.Interface2String(log.WinLog.EventData["ParentProcessName"])
	process_create.When = log.TimeStamp
	return process_create
}
