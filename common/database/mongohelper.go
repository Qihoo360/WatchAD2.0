package database

import (
	"context"
	"fmt"
	"iatp/common/logger"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/bsonx"

	"go.mongodb.org/mongo-driver/bson"

	"go.mongodb.org/mongo-driver/mongo"
)

type Mgo struct {
	database   string
	collection string
	client     *mongo.Client
}

func NewMgo(database, collection string) *Mgo {
	return &Mgo{
		database:   database,
		collection: collection,
		client:     Client,
	}
}

// 查询单条数据
func (m *Mgo) FindOne(filter interface{}) *mongo.SingleResult {
	if collection, err := m.client.Database(m.database).Collection(m.collection).Clone(); err != nil {
		// TODO: 发送数据库异常告警
		return nil
	} else {
		singleResult := collection.FindOne(context.TODO(), filter)
		return singleResult
	}
}

// 插入单条数据
func (m *Mgo) InsertOne(value interface{}) *mongo.InsertOneResult {
	if collection, err := m.client.Database(m.database).Collection(m.collection).Clone(); err != nil {
		// TODO: 发送数据库写入异常告警
		return nil
	} else {
		insertResult, _ := collection.InsertOne(context.TODO(), value)
		return insertResult
	}
}

func (m *Mgo) FindAll(filter interface{}) *mongo.Cursor {
	if collection, err := m.client.Database(m.database).Collection(m.collection).Clone(); err != nil {
		// TODO: 发送数据库异常告警
		return nil
	} else {
		cursor, err := collection.Find(context.TODO(), filter)
		if err != nil {
			// TODO: 发送查找失败告警
			return nil
		}
		return cursor
	}
}

// Sort 查询
func (m *Mgo) FindAllSort(filter interface{}, sort_field bson.D) *mongo.Cursor {
	if collection, err := m.client.Database(m.database).Collection(m.collection).Clone(); err != nil {
		// TODO: 发送数据库异常告警
		return nil
	} else {
		var findoptions *options.FindOptions = new(options.FindOptions)
		findoptions.SetSort(sort_field)
		findoptions.SetLimit(1024000000000)
		cursor, err := collection.Find(context.TODO(), filter, findoptions)
		if err != nil {
			// TODO: 发送查找失败告警
			return nil
		}
		return cursor
	}
}

// 批量写入
func (m *Mgo) InsertMany(value []interface{}) *mongo.InsertManyResult {
	if collection, err := m.client.Database(m.database).Collection(m.collection).Clone(); err != nil {
		// TODO: 发送数据库异常告警
		return nil
	} else {
		if insertManyResult, err := collection.InsertMany(context.TODO(), value); err != nil {
			// TODO: 发送写入失败告警
			return nil
		} else {
			return insertManyResult
		}
	}
}

// 更新数据库通过ObjectID过滤
func (m *Mgo) UpdateOne(filter interface{}, value interface{}) *mongo.UpdateResult {
	if collection, err := m.client.Database(m.database).Collection(m.collection).Clone(); err != nil {
		// TODO: 发送数据库异常告警
		return nil
	} else {
		updateResult, err := collection.UpdateOne(context.TODO(), filter, value)
		if err != nil {
			// TODO: 发送更新失败告警
			logger.IatpLogger.WithFields(
				logrus.Fields{
					"mongo_database":   m.database,
					"mongo_collection": m.collection,
					"error":            err.Error(),
				},
			).Errorln("Mongo 更新字段失败")
			return nil
		}
		return updateResult
	}
}

// 替换
func (m *Mgo) ReplaceOne(filter interface{}, value interface{}, opts ...*options.ReplaceOptions) *mongo.UpdateResult {
	if collection, err := m.client.Database(m.database).Collection(m.collection).Clone(); err != nil {
		// TODO: 发送数据库异常告警
		return nil
	} else {
		replaceResult, err := collection.ReplaceOne(context.TODO(), filter, value, opts...)
		if err != nil {
			// TODO: 发送更新失败告警
			logger.IatpLogger.WithFields(
				logrus.Fields{
					"mongo_database":   m.database,
					"mongo_collection": m.collection,
					"error":            err.Error(),
				},
			).Errorln("Mongo 替换字段失败")
			return nil
		}
		return replaceResult
	}
}

// 返回所有collections
func (m *Mgo) GetAllCollectionNames() []string {
	collections, err := m.client.Database(m.database).ListCollectionNames(context.TODO(), bson.M{})
	if err != nil {
		//TODO: 发送collections查找失败告警
		return []string{}
	}
	return collections
}

// 创建缓存collection
func (m *Mgo) CreateCacheCollection(cache_index string, cacheTime int32) error {
	indexModule := mongo.IndexModel{
		Keys: bsonx.Doc{
			{fmt.Sprintf("%s", cache_index), bsonx.Int32(1)},
		},
		Options: options.Index().SetExpireAfterSeconds(cacheTime),
	}
	_, err := m.client.Database(m.database).Collection(m.collection).Indexes().CreateOne(context.Background(), indexModule)
	if err != nil {
		return fmt.Errorf("%s-%s缓存表创建失败, %v", m.database, m.collection, err)
	}
	return nil
}

// 设置index
func (m *Mgo) CreateCollectionIndex(index string) error {
	indexModule := mongo.IndexModel{
		Keys: bson.M{
			index: 1,
		},
		Options: nil,
	}
	_, err := m.client.Database(m.database).Collection(m.collection).Indexes().CreateOne(context.Background(), indexModule)
	if err != nil {
		return fmt.Errorf("%s-%s设置Index失败, %v", m.database, m.collection, err)
	}
	return nil
}

func (m *Mgo) CreateCollectionTextIndex(index string) error {
	indexModule := mongo.IndexModel{
		Keys: bsonx.Doc{
			{
				Key: index,
			},
		},
	}

	_, err := m.client.Database(m.database).Collection(m.collection).Indexes().CreateOne(context.Background(), indexModule)
	if err != nil {
		return fmt.Errorf("%s-%s设置Index失败, %v", m.database, m.collection, err)
	}
	return nil
}

// 聚合查询
func (m *Mgo) AggregateSearchAll(match bson.D, group bson.D) *mongo.Cursor {
	if collection, err := m.client.Database(m.database).Collection(m.collection).Clone(); err != nil {
		// TODO: 发送数据库异常告警
		return nil
	} else {
		cursors, err := collection.Aggregate(context.TODO(), mongo.Pipeline{match, group})
		if err != nil {
			return nil
		}
		return cursors
	}
}

// 按搜索删除
func (m *Mgo) DeleteOne(filter interface{}) *mongo.DeleteResult {
	if collection, err := m.client.Database(m.database).Collection(m.collection).Clone(); err != nil {
		// TODO: 发送数据库异常告警
		return nil
	} else {
		deleteResult, _ := collection.DeleteOne(context.TODO(), filter)
		return deleteResult
	}
}

// 删除全部
func (m *Mgo) DeleteMany(filter interface{}) *mongo.DeleteResult {
	if collection, err := m.client.Database(m.database).Collection(m.collection).Clone(); err != nil {
		// TODO: 发送数据库异常告警
		return nil
	} else {
		deleteResult, _ := collection.DeleteMany(context.TODO(), filter)
		return deleteResult
	}
}

// 分页查询
// param page: 页码
// param perPage: 每页大小
func (m *Mgo) PagingSearch(filter interface{}, page, perPage int) *mongo.Cursor {
	skip := int64((page - 1) * perPage)
	limit := int64(perPage)

	opts := options.FindOptions{
		Skip:  &skip,
		Limit: &limit,
	}

	if collection, err := m.client.Database(m.database).Collection(m.collection).Clone(); err != nil {
		// TODO: 发送数据库异常告警
		return nil
	} else {
		cursor, err := collection.Find(context.TODO(), filter, &opts)
		if err != nil {
			// TODO: 发送查找失败告警
			return nil
		}
		return cursor
	}
}
