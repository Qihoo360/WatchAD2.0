package common

import (
	"context"
	"iatp/setting"

	"go.mongodb.org/mongo-driver/bson"
)

type Source struct {
	SourceName   string            // 来源名
	SourceType   string            // 来源类型，目前只支持kafka
	SourceConfig KafkaSourceConfig // 类型相应的配置信息
	SourceStatus bool              // 来源状态
	SourceEngine string            // 该消息来源指定的检测引擎
}

type KafkaSourceConfig struct {
	Brokers  string `bson:"brokers"`
	Topics   string `bson:"topics"`
	Version  string `bson:"version"`
	Group    string `bson:"group"`
	Assignor string `bson:"assignor"`
	Oldest   bool   `bson:"oldest"`
}

// 返回所有消息源配置
func GetAllSourceMessageConfig() []Source {
	var sourceMsgConfig Source
	var sources []Source = make([]Source, 0)

	sourceCursor := setting.SourceMongo.FindAll(bson.M{})

	for sourceCursor.Next(context.TODO()) {
		sourceCursor.Decode(&sourceMsgConfig)
		sources = append(sources, sourceMsgConfig)
	}
	return sources
}

func (s *Source) RegisterSource() {
	var source_config Source

	if err := setting.SourceMongo.FindOne(bson.M{"sourceengine": s.SourceEngine}).Decode(&source_config); err != nil {
		setting.SourceMongo.InsertOne(s)
	}
	//  else {
	// 	config, _ := json.Marshal(source_config)
	// 	fmt.Printf("[-]已存在 %s 相关配置\n旧配置:\n%s\n", s.SourceEngine, string(config))

	// 	setting.SourceMongo.UpdateOne(bson.M{"sourceengine": s.SourceEngine}, bson.M{
	// 		"$set": bson.D{
	// 			{Key: "sourcename", Value: s.SourceName},
	// 			{Key: "sourceconfig.brokers", Value: s.SourceConfig.Brokers},
	// 			{Key: "sourceconfig.topics", Value: s.SourceConfig.Topics},
	// 			{Key: "sourceconfig.group", Value: s.SourceConfig.Group},
	// 		},
	// 	})

	// 	setting.SourceMongo.FindOne(bson.M{"sourceengine": s.SourceEngine}).Decode(&source_config)
	// 	config, _ = json.Marshal(source_config)
	// 	fmt.Printf("[+]更新完成\n新配置:\n%s\n", string(config))
	// }
}
