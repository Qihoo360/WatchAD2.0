package services

import (
	"context"
	"iatp/common"
	"iatp/common/domain"
	"iatp/setting"

	"go.mongodb.org/mongo-driver/bson"
)

type SettingService interface {
	// 根据设置名称获取设置项信息
	GetSettingByName(setting_name string) bson.M
	// 更新设置
	SaveSettingByName(setting_name string, setting_val interface{}, description string) error
	// 返回来源采集配置 ata_source
	GetSourceSetting() []common.Source
	// 数据源输出配置
	GetOutSourceSetting() *common.OutSource
	// 配置Domain相关 ata_domain
	GetDomainSetting() []domain.Domain
	SaveSourceSetting(setting_val []common.Source) error
	SaveOutSourceSetting(setting_val common.OutSource) error
	SaveDomainSetting(setting_val []domain.Domain) error
}

type settingService struct{}

func NewSettingService() SettingService {
	return &settingService{}
}

func (s *settingService) GetSettingByName(setting_name string) bson.M {
	var result bson.M

	setting.SettingsMongo.FindOne(bson.M{"name": setting_name}).Decode(&result)

	return result
}

func (s *settingService) SaveSettingByName(setting_name string, setting_val interface{}, description string) error {
	var set setting.Setting
	if err := setting.SettingsMongo.FindOne(bson.M{"name": setting_name}).Decode(&set); err != nil {
		setting.SettingsMongo.InsertOne(setting.Setting{
			Name:        setting_name,
			Value:       setting_val,
			Description: description,
		})
	}
	setting.SettingsMongo.UpdateOne(bson.M{"name": setting_name}, bson.M{
		"$set": bson.M{
			"value": setting_val,
		},
	})
	return nil
}

func (s *settingService) GetSourceSetting() []common.Source {
	var result []common.Source = make([]common.Source, 0)

	setting.SourceMongo.FindAll(bson.M{}).All(context.TODO(), &result)
	return result
}

func (s *settingService) GetOutSourceSetting() *common.OutSource {

	var result []common.OutSource = make([]common.OutSource, 0)
	setting.OutSourceMongo.FindAll(bson.M{}).All(context.TODO(), &result)
	if result != nil && len(result) == 1 {
		return &result[0]
	}
	return nil
}

func (s *settingService) SaveSourceSetting(setting_val []common.Source) error {
	var tmp common.Source
	for _, val := range setting_val {
		if err := setting.SourceMongo.FindOne(bson.M{"sourcename": val.SourceName}).Decode(&tmp); err != nil {
			setting.SourceMongo.InsertOne(val)
		} else {
			setting.SourceMongo.UpdateOne(bson.M{"sourcename": val.SourceName}, bson.M{
				"$set": bson.M{
					"sourceconfig": val.SourceConfig,
					"sourceengine": val.SourceEngine,
					"sourcestatus": val.SourceStatus,
				}})
		}
	}
	return nil
}

func (s *settingService) SaveOutSourceSetting(val common.OutSource) error {

	var tmp common.OutSource
	//for _, val := range setting_val {
	if err := setting.OutSourceMongo.FindOne(bson.M{"address": val.Address}).Decode(&tmp); err != nil {
		setting.OutSourceMongo.DeleteMany(bson.M{}) // NOTE: 只保留一条数据
		setting.OutSourceMongo.InsertOne(val)
	} else {
		setting.OutSourceMongo.UpdateOne(bson.M{"address": val.Address}, bson.M{
			"$set": bson.M{
				"topic": val.Topic,
			}})
	}
	//}
	return nil
}

func (s *settingService) GetDomainSetting() []domain.Domain {
	var result []domain.Domain = make([]domain.Domain, 0)

	setting.DomainMongo.FindAll(bson.M{}).All(context.TODO(), &result)
	return result
}

func (s *settingService) SaveDomainSetting(setting_val []domain.Domain) error {
	var tmp domain.Domain
	for _, val := range setting_val {
		if err := setting.DomainMongo.FindOne(bson.M{"domainname": val.DomainName}).Decode(&tmp); err != nil {
			setting.DomainMongo.InsertOne(val)
		} else {
			setting.DomainMongo.UpdateOne(bson.M{"domainname": val.DomainName}, bson.M{
				"$set": bson.M{
					"domainserver":   val.DomainServer,
					"username":       val.UserName,
					"password":       val.PassWord,
					"domaincontrols": val.DomainControls,
					"netbiosdomain":  val.NetbiosDomain,
					"ssl":            val.SSL,
					"kdcservername":  val.KDCServerName,
				}})
		}
	}
	return nil
}
