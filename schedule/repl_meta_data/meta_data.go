package meta_data

import (
	"context"
	"fmt"
	"iatp/common/domain"
	l "iatp/common/ldap"
	"iatp/common/logger"
	"iatp/setting"
	"iatp/tools"
	"net"
	"strings"

	xj "github.com/basgys/goxml2json"
	"github.com/go-ldap/ldap/v3"
	jsoniter "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type ReplMetaData struct {
	DN       string     `json:"dn" bson:"dn"`
	Control  string     `json:"control" bson:"control"`
	MetaData []MetaData `json:"meta_data" bson:"meta_data"`
	SHA      string     `json:"sha" bson:"sha"`
}

type MetaData struct {
	PSZAttributeName                   string `json:"pszAttributeName" bson:"pszAttributeName"`
	DWVersion                          string `json:"dwVersion" bson:"dwVersion"`
	FTimeLastOriginatingChange         string `json:"ftimeLastOriginatingChange" bson:"ftimeLastOriginatingChange"`
	UUIDLastOriginatingDsaInvocationID string `json:"uuidLastOriginatingDsaInvocationID" bson:"uuidLastOriginatingDsaInvocationID"`
	USNOriginatingChange               string `json:"usnOriginatingChange" bson:"usnOriginatingChange"`
	USNLocalChange                     string `json:"usnLocalChange" bson:"usnLocalChange"`
	PSZLastOriginatingDsaDN            string `json:"pszLastOriginatingDsaDN" bson:"pszLastOriginatingDsaDN"`
}

type DS_REPL_ATTR_META_DATA_2 struct {
	DS_REPL_ATTR_META_DATA MetaData `json:"DS_REPL_ATTR_META_DATA" bson:"DS_REPL_ATTR_META_DATA"`
}

func NewReplMetaData() *ReplMetaData {
	return &ReplMetaData{}
}

func (r *ReplMetaData) Run() {
	// 定义注册时间
	cursor := setting.DomainMongo.FindAll(bson.M{})

	var d domain.Domain

	for cursor.Next(context.TODO()) {
		cursor.Decode(&d)

		for _, control := range d.DomainControls {
			addr, err := net.ResolveIPAddr("ip", fmt.Sprintf("%s.%s", control, d.DomainName))
			if err != nil {
				logger.IatpLogger.WithFields(
					logrus.Fields{
						"host_name": fmt.Sprintf("%s.%s", control, d.DomainName),
						"error":     err.Error(),
					},
				).Errorln("主机IP解析失败")
			} else {
				domain_ldap := l.NewLdap(addr.String(), d.UserName, d.PassWord, d.GetDomainScope(), d.SSL)
				domain_ldap.PageSearchHandler("(objectclass=*)", []string{"dn", "msDS-ReplAttributeMetaData"}, 100, control, ReplMetaDataSave)
			}
		}

	}
}

func ReplMetaDataSave(entry *ldap.Entry, control_server string) {
	repl_meta_data := ReplMetaData{DN: "", MetaData: make([]MetaData, 0)}
	repl_meta_data.DN = entry.DN
	repl_meta_data.Control = control_server
	repl_meta_data.MetaData = MetaData2Json(entry.GetAttributeValues("msDS-ReplAttributeMetaData"))
	repl_meta_data.SHA = tools.GetSha1s(entry.GetAttributeValues("msDS-ReplAttributeMetaData"))

	var mongo_repl_meta_data ReplMetaData
	FilterResult := setting.ReplMetaDataMongo.FindOne(bson.M{"dn": repl_meta_data.DN, "control": repl_meta_data.Control})

	if err := FilterResult.Decode(&mongo_repl_meta_data); err == mongo.ErrNilDocument || err == mongo.ErrNoDocuments {
		setting.ReplMetaDataMongo.InsertOne(repl_meta_data)
	} else if err == nil {
		// 数据库中已存储
		if mongo_repl_meta_data.SHA != repl_meta_data.SHA {
			//TODO: 待删除,测试
			// fmt.Println(mongo_repl_meta_data.DN)
			var result bson.M
			FilterResult.Decode(&result)
			setting.ReplMetaDataMongo.UpdateOne(bson.M{"_id": result["_id"]}, bson.D{
				{"$set", repl_meta_data},
			})
		}
	}
}

func MetaData2Json(Data []string) []MetaData {
	JsonMetaData := make([]MetaData, 0)
	for _, v := range Data {
		if cover_json, err := xj.Convert(strings.NewReader(v)); err != nil {
			fmt.Printf("MetaData2Json: %v", err)
		} else {
			var meta_data DS_REPL_ATTR_META_DATA_2
			json.Unmarshal(cover_json.Bytes(), &meta_data)
			JsonMetaData = append(JsonMetaData, meta_data.DS_REPL_ATTR_META_DATA)
		}
	}
	return JsonMetaData
}
