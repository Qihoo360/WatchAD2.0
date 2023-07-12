package domain_schedule

import (
	"iatp/common/domain"
	ldap_tool "iatp/common/ldap"
	"iatp/setting"
	"iatp/tools"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type HighRiskUser struct {
	Name  string              `bson:"name"`
	Value map[string][]string `bson:"value"`
}

func NewHighRiskUser() *HighRiskUser {
	return &HighRiskUser{}
}

func (r *HighRiskUser) Run() {

	// 获取域内关键用户(adminCount=1)
	high_risk_user := NewHighRiskUser()
	high_risk_user.Name = "high_risk_account"
	high_risk_user.Value = make(map[string][]string)

	for _, v := range domain.GetAllDomain() {
		ldap_client := ldap_tool.NewLdap(v.DomainServer, v.UserName, v.PassWord, v.GetDomainScope(), v.SSL)
		entrys := ldap_client.SearchHighRiskAccount()
		for _, entry := range entrys {
			high_risk_user.Value[v.NetbiosDomain] = append(high_risk_user.Value[v.NetbiosDomain], entry.GetAttributeValue("sAMAccountName"))
		}
	}

	var set HighRiskUser
	high_risk_setting := setting.SettingsMongo.FindOne(bson.M{
		"name": "high_risk_account",
	})

	err := high_risk_setting.Decode(&set)
	if err == mongo.ErrNilDocument || err == mongo.ErrNoDocuments {
		setting.SettingsMongo.InsertOne(high_risk_user)
	} else if err == nil {
		// 合并高危用户
		for k := range high_risk_user.Value {
			if set_value, ok := set.Value[k]; ok {
				high_risk_user.Value[k] = tools.RemoveDuplicateElement(append(high_risk_user.Value[k], set_value...))
			}
		}
		setting.SettingsMongo.UpdateOne(bson.M{"name": "high_risk_account"}, bson.M{"$set": high_risk_user})
	} else {
		return
	}
}
