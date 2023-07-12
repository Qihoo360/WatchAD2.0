package repositories

import (
	"context"
	"iatp/detect_plugins"
	"iatp/setting"
	"sync"

	"go.mongodb.org/mongo-driver/bson"
)

type Query func(filter bson.M) (bool, []*detect_plugins.PluginAlarm)
type Action func(alarm []*detect_plugins.PluginAlarm) bool

type AlarmRepository interface {
	// query:  搜索条件
	// action: 符合条件的值先关的操作方法
	// limit:  查询值范围
	// mode:   查询方式
	Exec(filter bson.M, query Query, action Action, mode int) (ok bool)

	// only one query
	Select(filter bson.M, query Query) (result *detect_plugins.PluginAlarm, found bool)
	SelectMany(filter bson.M, limit int) (result []*detect_plugins.PluginAlarm)
	AggregateSearch(match bson.D, group bson.D) (result []bson.M)

	// 更新字段
	UpdateOne(filter bson.M, target interface{}) (updatedCount int64)
}

type alarmMemoryRepository struct {
	mu sync.RWMutex
}

func NewAlarmRepository() AlarmRepository {
	return &alarmMemoryRepository{}
}

const (
	ReadOnlyMode = iota
	ReadWriteMode
)

func (r *alarmMemoryRepository) Exec(filter bson.M, query Query, action Action, mode int) (ok bool) {
	if mode == ReadOnlyMode {
		r.mu.RLock()
		defer r.mu.RUnlock()
	} else {
		r.mu.Lock()
		defer r.mu.Unlock()
	}

	ok, result := query(filter)

	if ok {
		ok = action(result)
		if ok {
			return
		}
	}
	return
}

func (r *alarmMemoryRepository) Select(filter bson.M, query Query) (result *detect_plugins.PluginAlarm, found bool) {
	found = r.Exec(filter, query, func(alarm []*detect_plugins.PluginAlarm) bool {
		result = alarm[0]
		return true
	}, ReadOnlyMode)

	if !found {
		result = nil
	}

	return
}

func (r *alarmMemoryRepository) SelectMany(filter bson.M, limit int) (result []*detect_plugins.PluginAlarm) {
	query := func(filter bson.M) (bool, []*detect_plugins.PluginAlarm) {
		loop := 0
		result := make([]*detect_plugins.PluginAlarm, 0)
		sort := bson.D{{"alarm_time", -1}}
		cursors := setting.AlarmMongoClient.FindAllSort(filter, sort)

		for cursors.Next(context.TODO()) {
			var alarm detect_plugins.PluginAlarm
			if err := cursors.Decode(&alarm); err == nil {
				if limit > 0 && loop >= limit {
					return true, result
				}
				result = append(result, &alarm)
				loop++
			}
		}

		return true, result
	}

	r.Exec(filter, query, func(alarm []*detect_plugins.PluginAlarm) bool {
		result = append(result, alarm...)
		return true
	}, ReadOnlyMode)

	return
}

func (r *alarmMemoryRepository) UpdateOne(filter bson.M, target interface{}) (updatedCount int64) {
	result := setting.AlarmMongoClient.UpdateOne(filter, target)

	return result.ModifiedCount
}

func (r *alarmMemoryRepository) AggregateSearch(match bson.D, group bson.D) (result []bson.M) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cursors := setting.AlarmMongoClient.AggregateSearchAll(match, group)
	if cursors == nil {
		return nil
	}

	err := cursors.All(context.TODO(), &result)
	if err != nil {
		return nil
	}

	return
}
