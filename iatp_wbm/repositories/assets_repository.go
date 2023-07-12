package repositories

import (
	"iatp/common/domain"
	ldap_tool "iatp/common/ldap"
	"strings"
	"sync"

	"github.com/go-ldap/ldap/v3"
)

type AssetsRepository interface {
	SearchByName(name string) (*ldap.Entry, string)
}

type assetsMemoryRepository struct {
	mu sync.RWMutex
}

func NewAssetsRepository() AssetsRepository {
	return &assetsMemoryRepository{}
}

func (m *assetsMemoryRepository) SearchByName(name string) (*ldap.Entry, string) {
	if name == "" || name == "-" {
		return nil, ""
	}

	name = strings.Split(strings.TrimRight(name, "$"), ".")[0]
	domains := domain.GetAllDomain()

	for _, d := range domains {
		ldap_client := ldap_tool.NewLdap(d.DomainServer, d.UserName, d.PassWord, d.GetDomainScope(), d.SSL)
		entrys := ldap_client.SearchComputerAccount(name, []string{"*"})
		for _, entry := range entrys {
			return entry, d.DomainName
		}
	}
	return nil, ""
}
