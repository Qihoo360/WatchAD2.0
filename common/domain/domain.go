package domain

import (
	"time"
)

// func init() {
// 	fmt.Println("创建SID-User缓存数据集....")
// 	exists := false
// 	for _, collection := range setting.UserSidCacheMongo.GetAllCollectionNames() {
// 		if collection == "ata_thridparty_ldap_sid" {
// 			exists = true
// 			break
// 		}
// 	}

// 	if !exists {
// 		// 缓存30天
// 		setting.UserSidCacheMongo.CreateCacheCollection("expiredata", 30*24*3600)
// 	}
// }

type Domain struct {
	DomainName     string   // 域名称 eg: domain.net
	DomainServer   string   // 域服务器 eg: 127.0.0.1
	KDCServerName  string   // KDC 服务器
	UserName       string   // 域账户 eg: domain\admin
	PassWord       string   // 域账户密码 eg: password
	DomainControls []string // 域控列表
	NetbiosDomain  string   // Netbios DomainName eg: domain
	SSL            bool     // 是否启用SSL
}

type User struct {
	UserName   string
	Sid        string
	ExpireData time.Time
	IsAdmin    bool
}
