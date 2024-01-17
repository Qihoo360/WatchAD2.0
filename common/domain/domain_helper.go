package domain

import (
	"context"
	"errors"
	"fmt"
	"iatp/common/database"
	ldap_tool "iatp/common/ldap"
	"iatp/setting"
	"iatp/tools/sddl"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/go-ldap/ldap/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

/*
根据域名获取域对象
param DSName: 域名 eg:contoso.com
*/
func NewDomain(DSName string) (*Domain, error) {
	netbiosDomain := FormatNetBiosDomain(DSName)
	var domain Domain
	if err := setting.DomainMongo.FindOne(bson.M{"netbiosdomain": netbiosDomain}).Decode(&domain); err != nil {
		return nil, fmt.Errorf("数据库中未注册该域信息, %v", err)
	}
	return &domain, nil
}

// 富化domain信息
func NewRichDomain(domain_name, domain_server, username, password string, ssl bool, kdcservername string) *Domain {
	domain := &Domain{
		DomainName:   domain_name,
		DomainServer: domain_server,
		UserName:     username,
		PassWord:     password,
		SSL:          ssl,
	}

	domain.DomainControls = domain.GetDomainControls()
	domain.NetbiosDomain = FormatNetBiosDomain(domain_name)

	if kdcservername == "" && len(domain.DomainControls) > 0 {
		domain.KDCServerName = fmt.Sprintf("%s.%s", strings.ToUpper(domain.DomainControls[0]), strings.ToUpper(domain.DomainName))
	} else {
		domain.KDCServerName = kdcservername
	}

	return domain
}

// 获取域内所有域管主机列表
func (domain *Domain) GetDomainControls() []string {
	ldapSearchObj := ldap_tool.NewLdap(domain.DomainServer, domain.UserName, domain.PassWord, "OU=Domain Controllers,"+domain.GetDomainScope(), domain.SSL)
	entrys := ldapSearchObj.SearchAllComputerAccount([]string{"dn"}, ldap.ScopeWholeSubtree)

	if entrys == nil {
		// 可能是LDAP查询失败导致
		return []string{}
	}

	controlServers := new([]string)
	for _, v := range entrys {
		*controlServers = append(*controlServers, strings.Replace(strings.Split(v.DN, ",")[0], "CN=", "", -1))
	}
	return *controlServers
}

// 将域信息注册到数据库中, 并查询域中其他的域控服务器
func (domain *Domain) RegisterDomain(client *database.Mgo) interface{} {
	result := client.InsertOne(domain)

	return result.InsertedID
}

// 根据Sid查询用户信息
// 返回值: 用户名 and 用户权限(true: 管理员, false: 普通用户)
func (domain *Domain) GetDomainUserBySid(sid string) (string, bool) {
	var user User

	// Well Known Sid
	if sid == "S-1-5-18" {
		return "LOCAL_SYSTEM", true
	}

	if err := setting.UserSidCacheMongo.FindOne(bson.M{"sid": sid}).Decode(&user); err == mongo.ErrNoDocuments {
		ldapObj := ldap_tool.NewLdap(domain.DomainServer, domain.UserName, domain.PassWord, domain.GetDomainScope(), domain.SSL)
		entry := ldapObj.SearchEntryBySid(sid, []string{"dn", "adminCount", "sAMAccountName"}, nil)
		if len(entry) == 0 {
			return sid, false
		}

		account_name := entry[0].GetAttributeValue("sAMAccountName")

		user.UserName = entry[0].DN
		user.ExpireData = time.Now()
		user.Sid = sid
		user.IsAdmin = domain.IsHighRiskAccount(account_name)

		setting.UserSidCacheMongo.InsertOne(user)
	}
	return user.UserName, user.IsAdmin
}

type GPO struct {
	GPOUUid    string `bson:"gpo_uuid"`
	GPOName    string `bson:"gpo_name"`
	GPOManager string `bson:"gpo_manager"`
	GPOPath    string `bson:"gpo_path"`
	GPOVersion string `bson:"gpo_version"`
}

// 根据uuid获取域内GPO配置信息
func (domain *Domain) GetDomainGPOByUUID(uuid string) (*GPO, error) {
	if !strings.HasPrefix(uuid, "{") && !strings.HasSuffix(uuid, "}") {
		return nil, errors.New(fmt.Sprintf("GetGPOByUUID - 不正确的UUID格式, uuid应该带有{}, 但是收到%v", uuid))
	}

	ldapObj := ldap_tool.NewLdap(domain.DomainServer, domain.UserName, domain.PassWord, fmt.Sprintf("CN=Policies,CN=System,%s", domain.GetDomainScope()), domain.SSL)
	entry := ldapObj.SearchGPOEntry(uuid)
	if len(entry) == 0 {
		return &GPO{GPOUUid: uuid}, errors.New(fmt.Sprintf("未查询到该GPO:%s的相关信息", uuid))
	}

	var owner string = sddl.NewSDDL().ReadBytes(entry[0].GetRawAttributeValue("nTSecurityDescriptor")).Owner.String()

	owner_entrys := ldapObj.SearchEntryBySid(owner, []string{"sAMAccountName"}, nil)

	if len(owner_entrys) > 0 {
		owner = owner_entrys[0].GetAttributeValue("sAMAccountName")
	}

	gpo := &GPO{
		GPOName:    entry[0].GetAttributeValue("displayName"),
		GPOUUid:    uuid,
		GPOManager: owner,
		GPOPath:    entry[0].GetAttributeValue("gPCFileSysPath"),
		GPOVersion: entry[0].GetAttributeValue("gPCFunctionalityVersion"),
	}

	return gpo, nil
}

// 判断用户是否属于加域用户
func (domain *Domain) IsJoinDomainAdminUser(user string) bool {
	val := setting.IatpSetting.ReadSet("join_domain_admin_user").(primitive.D).Map()[domain.NetbiosDomain]
	if val != nil {
		for _, v := range val.(primitive.A) {
			if v == user {
				return true
			}
		}
	}

	return false
}

// 根据域名获取根scope
func (domain *Domain) GetDomainScope() string {
	domain_strs := strings.Split(domain.DomainName, `.`)

	for k, v := range domain_strs {
		domain_strs[k] = "DC=" + v
	}

	return strings.Join(domain_strs, `,`)
}

// 判断机器账户是否属于域控制器账户
func (domain *Domain) JudgeDCAccount(machine_account string) bool {
	if !strings.HasSuffix(machine_account, "$") {
		return false
	}

	for _, v := range domain.DomainControls {
		if strings.EqualFold(v, strings.TrimSuffix(machine_account, "$")) {
			return true
		}
	}

	return false
}

// 获取用户DN
func (domain *Domain) GetUserDN(cn string) string {

	ldap_client := ldap_tool.NewLdap(domain.DomainServer, domain.UserName, domain.PassWord, domain.GetDomainScope(), domain.SSL)
	entrys := ldap_client.SearchEntryByCN(cn, []string{"name"}, nil)
	if entrys != nil && len(entrys) > 0 {
		return entrys[0].DN
	}
	return ""
}

// 判断用户是否在域中
func (domain *Domain) IsExistUser(cn string) bool {

	ldap_client := ldap_tool.NewLdap(domain.DomainServer, domain.UserName, domain.PassWord, domain.GetDomainScope(), domain.SSL)
	entrys := ldap_client.SearchEntryByCN(cn, []string{"displayName"}, nil)
	return entrys != nil && len(entrys) > 0
}

// 判断域内高风险账户
func (domain *Domain) IsHighRiskAccount(sAMAccountName string) bool {
	val := setting.IatpSetting.ReadSet("high_risk_account").(primitive.D).Map()[domain.NetbiosDomain]

	// 2021-07-22 新增域控机器账户也属于高风险账户
	if strings.HasSuffix(sAMAccountName, "$") {
		return domain.JudgeDCAccount(sAMAccountName)
	}

	if val != nil {
		for _, v := range val.(primitive.A) {
			if strings.EqualFold(v.(string), sAMAccountName) {
				return true
			}
		}
	}

	// 查询ldap信息
	ldapObj := ldap_tool.NewLdap(domain.DomainServer, domain.UserName, domain.PassWord, domain.GetDomainScope(), domain.SSL)
	entry, err := ldapObj.Search(fmt.Sprintf("(sAMAccountName=%s)", sAMAccountName), []string{"dn", "adminCount", "sAMAccountName"}, nil)
	if len(entry) == 0 || err != nil {
		return false
	}

	// 查询ldap admincount 属性判定
	admin := entry[0].GetAttributeValue("adminCount")
	return admin == "1"
}

// Domain to NetBios Domain
func FormatNetBiosDomain(domainName string) string {
	if !strings.Contains(domainName, ".") {
		return strings.ToUpper(domainName)
	} else {
		return strings.ToUpper(strings.Split(domainName, ".")[0])
	}
}

// 获取配置中所有域信息
func GetAllDomain() []Domain {
	domains := make([]Domain, 0)
	cursors := setting.DomainMongo.FindAll(bson.M{})

	var err error
	for cursors.Next(context.TODO()) {
		var domain Domain
		if err = cursors.Decode(&domain); err == nil {
			domains = append(domains, domain)
		}
	}

	return domains
}
