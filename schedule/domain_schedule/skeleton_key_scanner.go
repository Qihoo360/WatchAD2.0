package domain_schedule

import (
	"fmt"
	"iatp/common/domain"
	ldap_tool "iatp/common/ldap"
	"math/rand"
	"strings"

	"gopkg.in/jcmturner/gokrb5.v4/client"
	"gopkg.in/jcmturner/gokrb5.v4/config"
)

type SkeletonKey struct{}

func NewSkeletonKey() *SkeletonKey {
	return &SkeletonKey{}
}

func (c *SkeletonKey) Run() {
	for _, d := range domain.GetAllDomain() {
		// 获取支持aes256的用户
		ldap_client := ldap_tool.NewLdap(d.DomainServer, d.UserName, d.PassWord, d.GetDomainScope(), d.SSL)
		entrys, _ := ldap_client.Search("(&(objectClass=Computer)(msds-supportedencryptiontypes>=8))", []string{"sAMAccountName"}, nil)
		if len(entrys) == 0 {
			continue
		}

		var length int = 0
		if len(entrys) > 50 {
			length = rand.Intn(len(entrys) - 50)
			entrys = entrys[length : length+50]
		}

		for _, entry := range entrys {

			// 获取所有域控主机
			for _, domain_control := range d.DomainControls {
				krb5_cfg, err := config.NewConfigFromString(c.generateKrb5Conf(d, fmt.Sprintf("%s.%s", domain_control, d.DomainName)))
				if err != nil {
					fmt.Printf("krb5 配置文件加载失败: %v\n", err)
					return
				}

				cli := client.NewClientWithPassword(entry.GetAttributeValue("sAMAccountName"), strings.ToUpper(d.DomainName), "")
				cli.WithConfig(krb5_cfg)
				cli.GoKrb5Conf.DisablePAFXFast = true
				err = cli.Login()
				if err != nil {
					fmt.Println(err)
				}
			}
		}

	}
}

func (c *SkeletonKey) generateKrb5Conf(d domain.Domain, kdc_server string) string {
	libdefaults := fmt.Sprintf(`
	default_realm = %s
	default_tgs_enctypes = aes256-cts-hmac-sha1-96
	default_tkt_enctypes = aes256-cts-hmac-sha1-96
	`, strings.ToUpper(d.DomainName))

	realm := `
	%s = {
		kdc = %s
		admin_server = %s
	}
	`

	var realms []string = make([]string, 0)

	realms = append(realms, fmt.Sprintf(realm, strings.ToUpper(d.DomainName),
		strings.ToUpper(kdc_server),
		strings.ToUpper(kdc_server),
	))

	krb5_conf := fmt.Sprintf(`
[libdefaults]
%s

[realms]
%s
	`, libdefaults, strings.Join(realms, "\n"))

	return krb5_conf
}
