package detect_plugins

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"iatp/common"
	"iatp/setting"
	"time"

	"github.com/Shopify/sarama"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var config *sarama.Config

const ALARM_IM_TEMP = `
[IATP 高危事件通知: %s ]

事件发生时间: %s
攻击者: %s
攻击者主机: %s
受害者: %s
受害者主机: %s
事件描述: %s
`

func init() {
	config = sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Producer.Timeout = 5 * time.Second
}

// 插件告警模板
type PluginAlarm struct {
	ObjectID            primitive.ObjectID `json:"_id" bson:"_id"`
	AlarmTime           time.Time          `json:"alarm_time" bson:"alarm_time"`
	PluginMeta          interface{}        `json:"plugin_meta" bson:"plugin_meta"`
	Attacker            string             `json:"attacker" bson:"attacker"`                         // 攻击者
	AttackerAddress     string             `json:"attacker_address" bson:"attacker_address"`         // 攻击者主机IP
	AttackerWorkStation string             `json:"attacker_workstation" bson:"attacker_workstation"` // 攻击者主机名
	Victim              string             `json:"victim" bson:"victim"`                             // 受害者
	VictimAddress       string             `json:"victim_address" bson:"victim_address"`             // 受害者主机IP
	VictimWorkStation   string             `json:"victim_workstation" bson:"victim_workstation"`
	AlarmLevel          string             `json:"alarm_level" bson:"alarm_level"` // 告警等级
	AlarmDesc           string             `json:"alarm_desc" bson:"alarm_desc"`   // 告警描述
	AlarmState          string             `json:"alarm_state" bson:"alarm_state"` // 告警处理状态
	AlarmCategory       string             `json:"alarm_category" bson:"alarm_category"`
	AlarmATTCk          string             `json:"att_ck" bson:"att_ck"`
	AlarmCount          int                `json:"alarm_count" bson:"alarm_count"`     // 最近发生次数
	SerialNumber        string             `json:"serial_number" bson:"serial_number"` // 序列号
	RawSystemEvent      interface{}        `json:"raw" bson:"raw"`                     // 原始日志
}

func NewPluginAlarm(alarm_level, alarm_desc, alarm_category, alarm_attck string, raw, meta interface{}, alarm_tuples AlarmTuples) *PluginAlarm {
	alarm := &PluginAlarm{
		AlarmTime:           time.Now(),
		PluginMeta:          meta,
		Attacker:            alarm_tuples.Attacker,
		AttackerWorkStation: alarm_tuples.AttackerWorkStation,
		Victim:              alarm_tuples.Victim,
		VictimWorkStation:   alarm_tuples.VictimWorkStation,
		AlarmLevel:          alarm_level,
		AlarmDesc:           alarm_desc,
		AlarmState:          "open",
		AlarmCategory:       alarm_category,
		AlarmATTCk:          alarm_attck,
		RawSystemEvent:      raw,
	}

	alarm.SerialNumber = alarm.GetUniqueID()
	return alarm
}

func (alarm *PluginAlarm) SendAlarm() {
	alarm.SendAlarmKafka()

	var alarm_result PluginAlarm

	// 查询最近一段时间内没有处理的告警中是否有相同事件产生
	filter_query := bson.M{"serial_number": alarm.GetUniqueID(), "alarm_state": "open", "alarm_time": bson.M{"$gt": time.Now().Add(-time.Minute * 5)}}
	cursors := setting.AlarmMongoClient.FindAll(filter_query)

	for cursors.Next(context.TODO()) {
		cursors.Decode(&alarm_result)

		alarm_result.AlarmCount = alarm_result.AlarmCount + 1
		setting.AlarmMongoClient.UpdateOne(bson.M{"_id": alarm_result.ObjectID}, bson.M{"$set": alarm_result})
		return
	}

	// 随机生成ObjectID
	alarm.ObjectID = primitive.NewObjectID()
	insert_result := setting.AlarmMongoClient.InsertOne(alarm)

	if insert_result == nil {
		fmt.Println("告警写入失败")
	}
}

func GetOutSourceSetting() []common.OutSource {

	var result []common.OutSource = make([]common.OutSource, 0)
	setting.OutSourceMongo.FindAll(bson.M{}).All(context.TODO(), &result)
	return result
}

func (alarm *PluginAlarm) SendAlarmKafka() {

	outsource := GetOutSourceSetting()
	if outsource != nil && len(outsource) == 1 { // 默认试用第一个
		address := outsource[0].Address
		topic := outsource[0].Topic
		if address == "" || topic == "" {
			return
		}
		sarama_client, err := sarama.NewSyncProducer([]string{address}, config)

		if err != nil {
			fmt.Printf("发送者创建失败: %v", err)
		}

		val, err := json.Marshal(alarm)
		if err != nil {
			fmt.Printf("json 编码失败: %v", err)
		}

		msg := &sarama.ProducerMessage{
			Topic: topic,
			Value: sarama.ByteEncoder(val),
		}

		_, _, err = sarama_client.SendMessage(msg)
		if err != nil {
			fmt.Printf("saram 告警发送到队列失败: %v\n", err)
		}

		sarama_client.Close()
	} else {
		fmt.Printf("获取输出配置失败：%v", outsource)
	}
}

func (alarm *PluginAlarm) GetUniqueID() string {
	var be_encrypted []byte = make([]byte, 0)

	be_encrypted = append(be_encrypted, []byte(alarm.Attacker)...)
	be_encrypted = append(be_encrypted, []byte(alarm.AttackerWorkStation)...)
	be_encrypted = append(be_encrypted, []byte(alarm.Victim)...)
	be_encrypted = append(be_encrypted, []byte(alarm.VictimWorkStation)...)

	sum := sha1.Sum(be_encrypted)
	return hex.EncodeToString(sum[:])
}

type AlarmTuples struct {
	Attacker            string `json:"attacker" bson:"attacker"` // 攻击者
	AttackerWorkStation string `json:"attacker_workstation" bson:"attacker_workstation"`
	AttackerAddress     string `json:"attacker_address" bson:"attacker_address"`
	Victim              string `json:"victim" bson:"victim"` // 受害者
	VictimWorkStation   string `json:"victim_workstation" bson:"victim_workstation"`
	VictimAddress       string `json:"victim_address" bson:"victim_address"`
}

func CreateAlarmTuples(attacker, attacker_workstation, victim, victim_workstation string) *AlarmTuples {
	return &AlarmTuples{
		Attacker:            attacker,
		AttackerWorkStation: attacker_workstation,
		Victim:              victim,
		VictimWorkStation:   victim_workstation,
	}
}

func QueryAlarm(filter interface{}) []*PluginAlarm {
	cursors := setting.AlarmMongoClient.FindAll(filter)
	var alarms []*PluginAlarm

	err := cursors.All(context.TODO(), &alarms)
	if err != nil {
		return nil
	}

	return alarms
}
