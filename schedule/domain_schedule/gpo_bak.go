package domain_schedule

import (
	"context"
	"fmt"
	"iatp/common/domain"
	l "iatp/common/ldap"
	"iatp/setting"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type GPLink struct {
	DN     string    `json:"dn" bson:"dn"`
	GPLink string    `json:"gPLink" bson:"gPLink"`
	Update time.Time `json:"update" bson:"update"`
}

func NewGPO() *GPLink {
	return &GPLink{}
}

func (g *GPLink) Run() {
	cursor := setting.DomainMongo.FindAll(bson.M{})

	var d domain.Domain

	for cursor.Next(context.TODO()) {
		cursor.Decode(&d)

		var result bson.M
		// high_risk_ou 配置了当前域的高危OU
		filter := bson.M{
			"name":                                   "high_risk_ou",
			fmt.Sprintf("value.%s", d.NetbiosDomain): bson.M{"$exists": true},
		}
		if err := setting.SettingsMongo.FindOne(filter).Decode(&result); err == nil {
			if result != nil {
				domain_ldap := l.NewLdap(d.DomainServer, d.UserName, d.PassWord, d.GetDomainScope(), d.SSL)
				for _, dn := range result["value"].(bson.M)[d.NetbiosDomain].(bson.A) {
					GpLinkSave(domain_ldap, dn)
				}
			}
		}
	}
}

func GpLinkSave(server *l.LdapServer, dn interface{}) {
	entrys, _ := server.Search(fmt.Sprintf("(distinguishedName=%s)", dn), []string{"gPLink"}, nil)

	if len(entrys) > 1 {
		fmt.Printf("查询 distinguishedName=%s 出现大于1个结果\n", dn)
		return
	}

	for _, entry := range entrys {
		var result bson.M
		g := GPLink{
			DN:     dn.(string),
			GPLink: entry.GetAttributeValue("gPLink"),
			Update: time.Now(),
		}
		if err := setting.GpoBackMongo.FindOne(bson.M{"dn": dn}).Decode(&result); err == mongo.ErrNoDocuments {
			// 未存储在数据库中
			setting.GpoBackMongo.InsertOne(g)
		} else if err == nil {
			// dn已经存储在数据库中
			setting.GpoBackMongo.UpdateOne(bson.M{"_id": result["_id"]}, bson.M{"$set": g})
		} else {
			fmt.Printf("gpo_bak schedule 查询数据库异常: %v\n", err)
			return
		}
	}
}
