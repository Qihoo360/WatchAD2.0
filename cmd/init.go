/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"iatp/common/database"
	"iatp/common/domain"
	"iatp/setting"
	"io/ioutil"
	"net/url"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/spf13/cobra"
)

var (
	MongoURI                                                    string
	domainname, domainserver, username, password, kdcservername string
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the application configuration",
	Long: `Initialize the application configuration. For example:

iatp init --mongourl mongodb://mongo:123456@127.0.0.1:7117,127.0.0.2:7117/?replicaSet=7117 --domainname "contoso.com" --domainserver "127.0.0.1" --password "password" --username "domain\administrator"
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if MongoURI == "" {
			fmt.Println("Must Set --mongourl.")
			return
		}

		// 初始化表索引配置
		if index, _ := cmd.Flags().GetBool("index"); index {
			initMongoIndex()
		}

		err := saveMongoConf()
		if err != nil {
			fmt.Println("mongo 配置信息保存失败")
			return
		}

		ssl, _ := cmd.Flags().GetBool("ssl")

		// 创建域相关配置
		if d, ok := addDomainConf(ssl); ok {
			// 初始化域相关设置信息
			initSettings(ssl, d)
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().StringVar(&domainname, "domainname", "", "Domain Name. eg: domain.net")
	initCmd.Flags().StringVar(&domainserver, "domainserver", "", "Domain Server. eg: 10.10.10.10")
	initCmd.Flags().StringVar(&username, "username", "", "Common Domain User Account. eg: ldap_security")
	initCmd.Flags().StringVar(&password, "password", "", "Common Domain User Account Password.")
	initCmd.Flags().StringVar(&kdcservername, "kdcservername", "", "KDC Server For Krb5")
	initCmd.Flags().Bool("ssl", false, "Whether to use SSL for connection LDAP.")
	initCmd.Flags().Bool("index", false, "Initialize mongo database table index.")

	initCmd.Flags().StringVar(&MongoURI, "mongourl", "", "Mongo URI. eg:mongodb://[username:password@]host1[:port1][,...hostN[:portN]][/[defaultauthdb][?options]]")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// initCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// initCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// 保存mongo信息
func saveMongoConf() error {
	return ioutil.WriteFile("/etc/iatp.conf", []byte(MongoURI), 0644)
}

func addDomainConf(ssl bool) (*domain.Domain, bool) {
	if domainname != "" && domainserver != "" && username != "" && password != "" {
		mgo_client := database.NewMgo("ata", "ata_domain")
		// TODO 新增 密码解码
		password, _ := url.QueryUnescape(password)
		d := domain.NewRichDomain(domainname, domainserver, username, password, ssl, kdcservername)
		if len(d.DomainControls) == 0 {
			fmt.Printf("[+] %s 域注册失败: 未查询到域控制器.\n", d.NetbiosDomain)
			return nil, false
		}

		insertID := d.RegisterDomain(mgo_client)
		if insertID != nil {
			fmt.Printf("[+] %s 域注册成功.\n", d.NetbiosDomain)
			fmt.Printf("[+] 数据编号: %s.\n", insertID.(primitive.ObjectID).Hex())

			out, _ := json.Marshal(d)
			fmt.Println(string(out))
			return d, true
		} else {
			fmt.Printf("[+] %s 域注册失败: 未成功写入到数据库.\n", d.NetbiosDomain)
			return nil, false
		}
	}

	return nil, false
}

// 初始化域相关设置项
// * join_domain_admin_user
// * certificate_activite
// * high_risk_ou
// * high_risk_account
func initSettings(ssl bool, d *domain.Domain) {
	mgo_client := database.NewMgo("ata", "ata_settings")

	var set setting.Setting

	for _, set_elem := range []map[string]string{
		{"name": "high_risk_account", "description": "高风险账户"},
		{"name": "join_domain_admin_user", "description": "加域管理员"},
		{"name": "certificate_activite", "description": "证书服务活动插件 - 可信的账户及认证来源"},
		{"name": "high_risk_ou", "description": "高风险OU"}} {
		if err := mgo_client.FindOne(bson.M{"name": set_elem["name"]}).Decode(&set); err != nil {
			mgo_client.InsertOne(setting.Setting{
				Name: set_elem["name"],
				Value: map[string]interface{}{
					d.NetbiosDomain: primitive.A{},
				},
				Description: set_elem["description"],
			})
		} else {
			if _, ok := set.Value.(primitive.D).Map()[d.NetbiosDomain]; !ok {
				val := set.Value.(primitive.D).Map()
				val[d.NetbiosDomain] = primitive.A{}
				mgo_client.UpdateOne(bson.M{"name": set.Name}, bson.M{
					"$set": bson.M{
						"value": val,
					},
				})
			}
		}
	}

	mgo_client.InsertOne(setting.Setting{
		Name:        "ntlm_relay_white_user_segment",
		Value:       primitive.A{},
		Description: "NTLM Relay 插件 - 对指定用户创建白名单，规则用户名:网段字符串",
	})
}

func initMongoIndex() {
	// 缓存1天
	fmt.Println("创建日志缓存....")
	setting.CacheMongo.CreateCacheCollection("timestamp", 3*24*3600)
	setting.CacheMongo.CreateCollectionIndex("event_type")

	setting.CacheMongo.CreateCacheCollection("when", 30*24*3600)
	setting.CacheMongo.CreateCollectionIndex("who")
	setting.CacheMongo.CreateCollectionIndex("when")
	setting.CacheMongo.CreateCollectionIndex("where")
	setting.CacheMongo.CreateCollectionIndex("logon_id")
	setting.CacheMongo.CreateCollectionIndex("from_host")
	setting.CacheMongo.CreateCollectionIndex("from_address")

	// process create
	setting.CacheMongo.CreateCollectionIndex("host_name")
	setting.CacheMongo.CreateCollectionIndex("subject_user_sid")
	setting.CacheMongo.CreateCollectionIndex("token_elevation_type")
	setting.CacheMongo.CreateCollectionTextIndex("parent_process_name")
	setting.CacheMongo.CreateCollectionTextIndex("process_name")
	setting.TicketCacheMongo.CreateCacheCollection("time_stamp", 24*3600)

	// user logon
	setting.TicketCacheMongo.CreateCacheCollection("when", 7*24*3600)
	setting.TicketCacheMongo.CreateCollectionIndex("crealm")
	setting.TicketCacheMongo.CreateCollectionIndex("requester")
	setting.TicketCacheMongo.CreateCollectionIndex("where")
	setting.TicketCacheMongo.CreateCollectionIndex("ticket")

	// learn
	setting.LearnMongo.CreateCollectionIndex("learntype")
	setting.LearnMongo.CreateCollectionIndex("logonuser")
	setting.LearnMongo.CreateCollectionIndex("requester")
	setting.LearnMongo.CreateCollectionIndex("when")
	setting.LearnMongo.CreateCollectionIndex("where")

	// schedule -> gpo_bak
	setting.GpoBackMongo.CreateCollectionIndex("ou")

	// schedule -> repl_meta_data
	setting.ReplMetaDataMongo.CreateCollectionIndex("dn")
	setting.ReplMetaDataMongo.CreateCollectionIndex("control")
	setting.ReplMetaDataMongo.CreateCollectionIndex("meta_data.pszAttributeName")
	setting.ReplMetaDataMongo.CreateCollectionIndex("meta_data.dwVersion")
	setting.ReplMetaDataMongo.CreateCollectionIndex("meta_data.ftimeLastOriginatingChange")
	setting.ReplMetaDataMongo.CreateCollectionIndex("meta_data.uuidLastOriginatingDsaInvocationID")
	setting.ReplMetaDataMongo.CreateCollectionIndex("meta_data.usnOriginatingChange")
	setting.ReplMetaDataMongo.CreateCollectionIndex("meta_data.usnLocalChange")
	setting.ReplMetaDataMongo.CreateCollectionIndex("meta_data.pszLastOriginatingDsaDN")

	// alert
	setting.AlarmMongoClient.CreateCollectionIndex("plugin_meta.systemplugin.plugin_name")
	setting.AlarmMongoClient.CreateCollectionIndex("raw.timestamp")
	setting.AlarmMongoClient.CreateCollectionIndex("victim_workstation")
	setting.AlarmMongoClient.CreateCollectionIndex("serial_number")

	// honeypot 1 month
	setting.HoneypotMongo.CreateCacheCollection("create_time", 30*34*3600)
}
