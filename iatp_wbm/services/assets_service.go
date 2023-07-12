package services

import (
	"fmt"
	domain2 "iatp/common/domain"
	ldap_tool "iatp/common/ldap"
	"iatp/iatp_wbm/repositories"
	"iatp/tools/sddl"
	"strconv"
)

type AssetsService interface {
	// 根据用户名获取资产信息
	SearchByName(name string) (result *Assets)
}

type assetsService struct {
	repo repositories.AssetsRepository
}

func NewAssetsService(repo repositories.AssetsRepository) AssetsService {
	return &assetsService{
		repo: repo,
	}
}

type Assets struct {
	AssetsName         string `json:"assets_name"`
	Owner              string `json:"owner"`
	SystemVersion      string `json:"system_version"` // 系统版本号
	DomainName         string `json:"domain_name"`
	IsDomainController bool   `json:"is_domain_controller"`
	IsSetLaps          bool   `json:"is_set_laps"`
}

func (s *assetsService) SearchByName(name string) (result *Assets) {
	entry, domain_name := s.repo.SearchByName(name)
	if entry == nil {
		return &Assets{
			AssetsName:    "-",
			Owner:         "-",
			SystemVersion: "-",
			DomainName:    "-",
		}
	}

	control, err := strconv.Atoi(entry.GetAttributeValue("userAccountControl"))
	if err != nil {
		control = 0
	}

	var owner string = sddl.NewSDDL().ReadBytes(entry.GetRawAttributeValue("nTSecurityDescriptor")).Owner.String()

	d, err := domain2.NewDomain(domain_name)
	if err == nil {
		ldap_client := ldap_tool.NewLdap(d.DomainServer, d.UserName, d.PassWord, d.GetDomainScope(), d.SSL)
		entrys := ldap_client.SearchEntryBySid(sddl.NewSDDL().ReadBytes(entry.GetRawAttributeValue("nTSecurityDescriptor")).Owner.String(), []string{"cn"}, nil)
		for _, entry := range entrys {
			owner = entry.GetAttributeValue("cn")
		}
	}

	return &Assets{
		AssetsName:         entry.GetAttributeValue("cn"),
		Owner:              owner,
		SystemVersion:      fmt.Sprintf("%s %s", entry.GetAttributeValue("operatingSystem"), entry.GetAttributeValue("operatingSystemVersion")),
		DomainName:         domain_name,
		IsDomainController: control&8192 == 8192,
		IsSetLaps:          entry.GetAttributeValue("ms-mcs-AdmPwdExpirationTime") != "",
	}
}
