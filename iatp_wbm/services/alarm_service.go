package services

import (
	"encoding/json"
	"fmt"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	system_plugin "iatp/detect_plugins/event_log"
	"iatp/iatp_wbm/repositories"
	"iatp/setting"
	"reflect"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AlarmService interface {
	// 获取所有未处理告警
	GetAllUntreatedAlarm() (result []*detect_plugins.PluginAlarm)
	// 获取所有告警
	GetAllAlarm() []*detect_plugins.PluginAlarm

	// 根据告警ID获取相关信息
	GetAlarmByObjectID(ObjectID string) *detect_plugins.PluginAlarm

	// 分页查询
	GetAlarmByPage(keywords, alarm_level, input_datetime_range, status, plugin_name string) (result []SearchResult)

	// 聚合查询
	GetAlarmGroupBy(keywords, alarm_level, input_datetime_range, group_field, status, plugin_name string) []bson.M

	// 根据告警ID 获取原始日志信息
	GetAlarmRawLog(objectID string) *RawLog
	// 更新告警状态
	UpdateAlarmStatus(id string, status string) bool

	// 告警测试
	GetAlarmTestResult(_select string, editor string) []TestResult
}

type alarmService struct {
	repo repositories.AlarmRepository
}

func NewAlarmService(repo repositories.AlarmRepository) AlarmService {
	return &alarmService{
		repo: repo,
	}
}

// 更新告警状态
func (s *alarmService) UpdateAlarmStatus(id string, status string) bool {
	ObjectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return false
	}

	res := s.repo.SelectMany(bson.M{"_id": ObjectID}, -1)
	if res[0].AlarmState == status {
		return true
	}

	count := s.repo.UpdateOne(bson.M{"_id": ObjectID}, bson.D{
		{"$set", bson.M{
			"alarm_state": status,
		}},
	})

	if count == 1 {
		return true
	} else {
		return false
	}
}

func (s *alarmService) GetAllUntreatedAlarm() (result []*detect_plugins.PluginAlarm) {
	return s.repo.SelectMany(bson.M{"alarm_state": "open"}, -1)
}

func (s *alarmService) GetAllAlarm() (result []*detect_plugins.PluginAlarm) {
	return s.repo.SelectMany(bson.M{}, -1)
}

func (s *alarmService) GetAlarmByObjectID(objectID string) (result *detect_plugins.PluginAlarm) {
	// convert string to ObjectID
	id, err := primitive.ObjectIDFromHex(objectID)
	if err != nil {
		return nil
	}

	result, _ = s.repo.Select(bson.M{"_id": id}, func(filter bson.M) (bool, []*detect_plugins.PluginAlarm) {
		var alarm detect_plugins.PluginAlarm
		result := make([]*detect_plugins.PluginAlarm, 0)
		if err := setting.AlarmMongoClient.FindOne(filter).Decode(&alarm); err != nil {
			return false, nil
		} else {
			return true, append(result, &alarm)
		}
	})

	return result
}

type RawLog struct {
	TimeStamp string      `json:"timestamp"`
	Tag       string      `json:"tag"`
	EventID   interface{} `json:"event_id"`
	HostName  string      `json:"host_name"`
	Event     interface{} `json:"event"`
}

func (s *alarmService) GetAlarmRawLog(objectID string) *RawLog {
	id, err := primitive.ObjectIDFromHex(objectID)
	if err != nil {
		return nil
	}

	result, _ := s.repo.Select(bson.M{"_id": id}, func(filter bson.M) (bool, []*detect_plugins.PluginAlarm) {
		var alarm detect_plugins.PluginAlarm
		result := make([]*detect_plugins.PluginAlarm, 0)
		if err := setting.AlarmMongoClient.FindOne(filter).Decode(&alarm); err != nil {
			return false, nil
		} else {
			return true, append(result, &alarm)
		}
	})

	if _, ok := result.RawSystemEvent.(primitive.D).Map()["winlog"]; ok {
		// windows log
		var event_data primitive.D = primitive.D{}

		if result.RawSystemEvent.(primitive.D).Map()["winlog"].(primitive.D).Map()["eventdata"] != nil {
			event_data = result.RawSystemEvent.(primitive.D).Map()["winlog"].(primitive.D).Map()["eventdata"].(primitive.D)
		}

		tags := make([]string, 0)
		if result.RawSystemEvent.(primitive.D).Map()["tags"] != nil {
			for _, v := range result.RawSystemEvent.(primitive.D).Map()["tags"].(primitive.A) {
				tags = append(tags, v.(string))
			}
		}

		return &RawLog{
			TimeStamp: result.RawSystemEvent.(primitive.D).Map()["timestamp"].(primitive.DateTime).Time().Format(time.RFC3339),
			Tag:       strings.Join(tags, ","),
			EventID:   result.RawSystemEvent.(primitive.D).Map()["winlog"].(primitive.D).Map()["eventid"].(int32),
			HostName:  result.RawSystemEvent.(primitive.D).Map()["winlog"].(primitive.D).Map()["computername"].(string),
			Event:     event_data,
		}
	} else if _, ok := result.RawSystemEvent.(primitive.D).Map()["request"]; ok {
		// traffic log
		return &RawLog{
			TimeStamp: result.RawSystemEvent.(primitive.D).Map()["timestamp"].(primitive.DateTime).Time().Format(time.RFC3339),
			Tag:       "",
			EventID:   result.RawSystemEvent.(primitive.D).Map()["type"].(string),
			HostName:  "",
			Event: map[string]interface{}{
				"request":  result.RawSystemEvent.(primitive.D).Map()["request"],
				"response": result.RawSystemEvent.(primitive.D).Map()["response"],
			},
		}
	} else if _, ok := result.RawSystemEvent.(primitive.D).Map()["alert"]; ok {
		// suricata log
		return &RawLog{
			TimeStamp: result.RawSystemEvent.(primitive.D).Map()["timestamp"].(primitive.DateTime).Time().Format(time.RFC3339),
			Tag:       "suricata",
			EventID:   result.RawSystemEvent.(primitive.D).Map()["alert"].(primitive.D).Map()["signature"].(string),
			HostName:  result.RawSystemEvent.(primitive.D).Map()["host"].(string),
			Event:     result.RawSystemEvent,
		}
	}

	return &RawLog{}
}

type SearchResult struct {
	ID                  string `json:"id"`
	TimeStamp           string `json:"alarm_time"`
	PluginName          string `json:"plugin_name"`
	PluginDesc          string `json:"plugin_desc"`
	PluginVersion       string `json:"plugin_version"`
	PluginAuthor        string `json:"plugin_author"`
	Attacker            string `json:"attacker"`
	AttackerWorkstation string `json:"attacker_workstation"`
	Victim              string `json:"victim"`
	VictimWorkstation   string `json:"victim_workstation"`
	AlarmLevel          string `json:"alarm_level"`
	AlarmDesc           string `json:"alarm_desc"`
	AlarmState          string `json:"alarm_state"`
}

func (s *alarmService) GetAlarmByPage(keywords, alarm_level, input_datetime_range, status, plugin_name string) (result []SearchResult) {
	filter := generateAlarmFilter(keywords, alarm_level, input_datetime_range, status, plugin_name)
	result = make([]SearchResult, 0)

	for _, v := range s.repo.SelectMany(filter, -1) {
		result = append(result, SearchResult{
			ID:                  v.ObjectID.Hex(),
			TimeStamp:           v.AlarmTime.Add(8 * time.Hour).Format(time.RFC3339),
			PluginName:          v.PluginMeta.(primitive.D).Map()["systemplugin"].(primitive.D).Map()["plugin_name"].(string),
			PluginDesc:          v.PluginMeta.(primitive.D).Map()["systemplugin"].(primitive.D).Map()["plugin_desc"].(string),
			PluginVersion:       v.PluginMeta.(primitive.D).Map()["systemplugin"].(primitive.D).Map()["plugin_version"].(string),
			PluginAuthor:        v.PluginMeta.(primitive.D).Map()["systemplugin"].(primitive.D).Map()["plugin_author"].(string),
			Attacker:            v.Attacker,
			AttackerWorkstation: v.AttackerWorkStation,
			Victim:              v.Victim,
			VictimWorkstation:   v.VictimWorkStation,
			AlarmLevel:          v.AlarmLevel,
			AlarmDesc:           v.AlarmDesc,
			AlarmState:          v.AlarmState,
		})
	}

	return result
}

func (s *alarmService) GetAlarmGroupBy(keywords, alarm_level, input_datetime_range, group_field, status, plugin_name string) []bson.M {
	filter := generateAlarmFilter(keywords, alarm_level, input_datetime_range, status, plugin_name)

	match := bson.D{{"$match", filter}}
	group := bson.D{{"$group", bson.D{{"_id", fmt.Sprintf("%s", group_field)}, {"count", bson.D{{"$sum", 1}}}}}}
	return s.repo.AggregateSearch(match, group)
}

func unix2time(unix_num int64) time.Time {
	tm := time.Unix(unix_num, 0)
	return tm
}

func generateAlarmFilter(keywords, alarm_level, input_datetime_range, status, plugin_name string) (filter bson.M) {
	filter = bson.M{}

	if alarm_level != "" && (alarm_level == "high" || alarm_level == "medium" || alarm_level == "information") {
		filter["alarm_level"] = alarm_level
	}

	if keywords != "" {
		filter["$or"] = []bson.M{
			{"alarm_desc": bson.M{"$regex": keywords}},
			{"attacker": bson.M{"$regex": keywords}},
			{"attacker_workstation": bson.M{"$regex": keywords}},
			{"victim": bson.M{"$regex": keywords}},
			{"victim_workstation": bson.M{"$regex": keywords}},
			{"plugin_meta.systemplugin.plugin_desc": bson.M{"$regex": keywords}},
		}
	}

	start_time, _ := strconv.Atoi(strings.Split(input_datetime_range, ",")[0])
	end_time, _ := strconv.Atoi(strings.Split(input_datetime_range, ",")[1])
	filter["alarm_time"] = bson.M{"$gte": unix2time(int64(start_time)), "$lte": unix2time(int64(end_time))}

	if status != "" {
		filter["alarm_state"] = status
	}

	if plugin_name != "" {
		plugins := strings.Split(plugin_name, ",")
		filter["plugin_meta.systemplugin.plugin_name"] = bson.M{
			"$in": plugins,
		}
	}

	return
}

type TestResult struct {
	PluginName  string `json:"plugin_name"`
	AlarmStatus string `json:"alarm_status"`
}

func (s *alarmService) GetAlarmTestResult(_select string, editor string) []TestResult {
	result := make([]TestResult, 0)
	var event_id interface{}
	var event interface{}

	setting.GetAllSettings()

	switch _select {
	case "event_log":
		system_plugin.RegisterPlugins()
		var system_event decoder.SystemEvent

		err := json.Unmarshal([]byte(editor), &system_event)
		if err != nil || reflect.DeepEqual(system_event, decoder.SystemEvent{}) {
			return result
		}

		event_id = system_event.WinLog.EventID
		event = system_event
	}

	for _, plugin := range detect_plugins.GetPlugins(event_id) {
		alarm := plugin.Detect(event)
		if alarm != nil {
			result = append(result, TestResult{
				PluginName:  reflect.ValueOf(plugin).Elem().FieldByName("SystemPlugin").Elem().FieldByName("PluginDesc").String(),
				AlarmStatus: "true",
			})
		} else {
			result = append(result, TestResult{
				PluginName:  reflect.ValueOf(plugin).Elem().FieldByName("SystemPlugin").Elem().FieldByName("PluginDesc").String(),
				AlarmStatus: "false",
			})
		}
	}

	return result
}
