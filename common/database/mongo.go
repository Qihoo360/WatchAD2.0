package database

import (
	"context"
	"fmt"
	"iatp/common/logger"
	"io/ioutil"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client

func init() {
	Client = mongoClient(readfile())
}

// 检查Mongodb 连接情况
func CheckConnect(client *mongo.Client) error {
	err := client.Ping(context.TODO(), nil)
	return fmt.Errorf("MongoDB 连接失败: %v", err)
}

// Mongodb连接池
func mongoClient(mongoUri string) *mongo.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 创建连接池
	if client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoUri).SetMaxPoolSize(4096)); err != nil {
		logger.IatpLogger.WithFields(
			logrus.Fields{
				"mongo_uri": mongoUri,
				"error":     err.Error(),
			},
		).Errorln("Mongo 连接池创建异常")
		return nil
	} else {
		return client
	}
}

func readfile() string {
	context, err := ioutil.ReadFile("/etc/iatp.conf")
	if err != nil {
		return "mongodb://mongo:123456@127.0.0.1:7117,127.0.0.1:7117/?authSource=admin&replicaSet=7117"
	}
	return string(context)
}
