package setting

import (
	"context"
	"iatp/common/logger"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

var IatpSetting *iatpSetting
var SettingLoad chan bool

func init() {
	IatpSetting = &iatpSetting{
		setting: make(map[string]interface{}),
		rw:      &sync.RWMutex{},
	}

	SettingLoad = make(chan bool)
}

type Setting struct {
	Name        string      `bson:"name"`
	Value       interface{} `bson:"value"`
	Description string      `bson:"description"`
}

type iatpSetting struct {
	rw      *sync.RWMutex
	setting map[string]interface{}
}

func (i *iatpSetting) ReadSet(set_name string) interface{} {
	i.rw.RLock()
	defer i.rw.RUnlock()

	return i.setting[set_name]
}

func (i *iatpSetting) WriteSet(set_name string, set_val interface{}) {
	i.rw.Lock()
	defer i.rw.Unlock()

	i.setting[set_name] = set_val
}

func GetAllSettings() {
	cursors := SettingsMongo.FindAll(bson.M{})
	var setting Setting

	for cursors.Next(context.TODO()) {
		cursors.Decode(&setting)
		IatpSetting.WriteSet(setting.Name, setting.Value)
	}
}

func Init(ctx context.Context) {
	GetAllSettings()
	// 配置加载完成
	SettingLoad <- true

	for {
		select {
		case <-time.After(5 * time.Minute):
			GetAllSettings()
		case <-ctx.Done():
			logger.IatpLogger.Infoln("定时配置加载任务退出")
			return
		}
	}
}
