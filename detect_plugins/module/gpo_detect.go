package module

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"iatp/common/domain"
	ldap_tool "iatp/common/ldap"
	smbshare "iatp/common/smb_share"
	"iatp/decoder/gpo"
	"iatp/tools"
	"io/ioutil"
	"log"
	"path"
	"path/filepath"
	"strings"
)

type GpoRegistry struct {
	RegistrySettings xml.Name   `xml:"RegistrySettings"`
	Registry         []registry `xml:"Registry"`
}

type registry struct {
	Properties properties `xml:"Properties"`
}

type properties struct {
	Name    string `xml:"name,attr"`
	Value   string `xml:"value,attr"`
	Type    string `xml:"type,attr"`
	Key     string `xml:"key,attr"`
	Hive    string `xml:"hive,attr"`
	Default string `xml:"default,attr"`
	Action  string `xml:"action,attr"`
}

type GPODetection struct {
}

func NewGPODetection() *GPODetection {
	return &GPODetection{}
}

func (d *GPODetection) Detection(gpoUuid string, domainName string) (report []string) {
	dg, err := domain.NewDomain(domainName)
	if err != nil {
		return
	}

	ldapClient := ldap_tool.NewLdap(dg.DomainServer, dg.UserName, dg.PassWord, dg.GetDomainScope(), dg.SSL)
	entrys := ldapClient.SearchGPOEntry(gpoUuid)
	if len(entrys) == 0 {
		return
	}

	gpoPath := entrys[0].GetAttributeValue("gPCFileSysPath")
	gpoPathFormat := strings.Split(gpoPath, "\\")
	s := smbshare.NewSmbDir(tools.GetRawUserName(dg.UserName), dg.PassWord, fmt.Sprintf("%s:445", dg.DomainServer), strings.Join(gpoPathFormat[:4], "\\"))
	files := s.ListFile(strings.Join(gpoPathFormat[4:], "\\"))
	for _, file := range files {
		// 检测
		switch file.FileName {
		// 注册表配置项
		case "Registry.xml":
			report = append(report, registryDetection(file.FileContext)...)
		case "ScheduledTasks.xml":
			report = append(report, "该GPO存在计划任务配置,需要审查计划任务的合规性")
			// {CFCF0F15-2955-42C5-86E5-A84843CC5F91}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
		}

		// 文件夹
		switch {
		case strings.Contains(file.FilePath, "Scripts\\Logon\\") || strings.Contains(file.FilePath, "Scripts\\Logoff\\"):
			report = append(report, "需要审查%v\\%v文件的合法性", file.FilePath, file.FileName)
		case strings.HasSuffix(file.FilePath, "\\Machine\\Applications") && path.Ext(file.FileName) == ".aas":
			// AAS 文件处理
			aas := gpo.NewAAS()
			aas.Decode(file.FileContext)
			if aas == nil {
				report = append(report, fmt.Sprintf("%s\\%s 文件不可被识别,需人工介入判断", file.FilePath, file.FileName))
			} else {
				report = append(report, fmt.Sprintf("需要审查%v\\%v文件的合法性", aas.ProductPublish.SourceListPublish.LaunchPath, aas.ProductInfo.PackageName))
			}
		}
	}

	return
}

// 注册表配置检测
func registryDetection(context []byte) (report []string) {
	r := &RegisterConfig{}
	config := r.LoadConfig()

	var gpoReg GpoRegistry
	err := xml.Unmarshal(context, &gpoReg)
	if err != nil {
		log.Printf("GPO配置 - GPO注册表配置结构化失败,报错内容: %v\n", err)
	}

	for _, v := range gpoReg.Registry {
		for _, c := range config {
			if v.Properties.Hive == c.RegistryHive && v.Properties.Key == c.RegistryKey && v.Properties.Name == c.RegistryName && v.Properties.Value == c.RegistryValue && v.Properties.Action == c.Action {
				raw := fmt.Sprintf(`<Properties action="%s" default="%s" hive="%s" key="%s" name="%s" type="%s" value="%s"/>`, v.Properties.Action, v.Properties.Default, v.Properties.Hive, v.Properties.Key, v.Properties.Name, v.Properties.Type, v.Properties.Value)
				report = append(report, fmt.Sprintf("%s: %s", c.Description, raw))
			}
		}
	}

	return
}

// TODO: Application 配置检测
// func applicationDetection() (report []string) {
// 	return
// }

// 注册表相关检测配置项
type RegisterConfig struct {
	Tag           string      `json:"tag"`
	RegistryHive  string      `json:"registry_hive"`
	RegistryKey   string      `json:"registry_key"`
	RegistryName  string      `json:"registry_name"`
	RegistryValue interface{} `json:"registry_value"`
	Action        string      `json:"action"`
	Description   string      `json:"description"`
}

func (r *RegisterConfig) LoadConfig() (configs []RegisterConfig) {
	configFile := fmt.Sprintf("%s/%s", filepath.Dir(tools.GetCurrentPath()), "gpo_audit_config/registry.json")
	f_context, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Printf("组策略 - 注册表检测配置项规则读取失败,报错内容: %v\n", err)
		return nil
	}

	err = json.Unmarshal(f_context, &configs)
	if err != nil {
		log.Printf("组策略 - 注册表检测配置项规则加载失败,报错内容: %v\n", err)
		return nil
	}
	return
}
