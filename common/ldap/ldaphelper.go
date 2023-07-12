package ldap_tool

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type LdapServer struct {
	Server   string
	UserName string
	PassWord string
	BaseDN   string
	SSL      bool
}

// LDAP 查询对象
func NewLdap(server, user_name, password, basedn string, ssl bool) *LdapServer {
	return &LdapServer{
		Server:   server,
		UserName: user_name,
		PassWord: password,
		BaseDN:   basedn,
		SSL:      ssl,
	}
}

// 获取ldap连接
func (l *LdapServer) ldapConnect() (*ldap.Conn, error) {
	conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", l.Server, 389))
	if err != nil {
		return nil, fmt.Errorf("LDAP 连接失败, %v", err)
	}

	// 设置超时时间
	conn.SetTimeout(5 * time.Second)

	err = conn.Bind(l.UserName, l.PassWord)
	if err != nil {
		return nil, fmt.Errorf("LDAP 绑定失败, %v", err)
	}

	return conn, nil
}

// TLS 方式连接ldap服务器
func (l *LdapServer) ldapTlsConnect() (*ldap.Conn, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", l.Server, 636), tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("LDAP TLS链接失败, %v", err)
	}

	err = conn.Bind(l.UserName, l.PassWord)
	if err != nil {
		return nil, fmt.Errorf("LDAP TLS 绑定失败, %v", err)
	}
	return conn, nil
}

// 检测账号密码是否正常
func (l *LdapServer) CheckConn() (bool, error) {
	var conn *ldap.Conn
	var err error
	if l.SSL {
		conn, err = l.ldapTlsConnect()
	} else {
		conn, err = l.ldapConnect()
	}

	if err != nil {
		return false, fmt.Errorf("LDAP 链接%s失败,%v", l.Server, err)
	}

	defer conn.Close()
	return true, nil
}

// LDAP简单查询DN
func (l *LdapServer) Search(filter string, attributes []string, control []ldap.Control) ([]*ldap.Entry, error) {
	var conn *ldap.Conn
	var err error
	if l.SSL {
		conn, err = l.ldapTlsConnect()
	} else {
		conn, err = l.ldapConnect()
	}

	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(l.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		control)

	ldapSearchResult, err := conn.Search(searchRequest)

	if err != nil {
		return nil, fmt.Errorf("ldap查询 filter:%s, scope:%s, attributes:%v 失败 %v", filter, l.BaseDN, attributes, err)
	}
	return ldapSearchResult.Entries, nil
}

func (l *LdapServer) SearchByScope(filter string, attributes []string, scope int) ([]*ldap.Entry, error) {
	var conn *ldap.Conn
	var err error
	if l.SSL {
		conn, err = l.ldapTlsConnect()
	} else {
		conn, err = l.ldapConnect()
	}

	if err != nil {
		return nil, fmt.Errorf("LDAP 链接%s:%s失败,%v", l.Server, "636", err)
	}
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(l.BaseDN,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil)

	ldapSearchResult, err := conn.Search(searchRequest)

	if err != nil {
		return nil, fmt.Errorf("ldap查询 filter:%s, scope:%s, attributes:%v 失败 %v", filter, l.BaseDN, attributes, err)
	}
	return ldapSearchResult.Entries, nil
}

// LDAP分页查询
func (l *LdapServer) PageSearch(filter string, attributes []string, PageSize uint32, scope int) ([]*ldap.Entry, error) {
	var conn *ldap.Conn
	var err error
	if l.SSL {
		conn, err = l.ldapTlsConnect()
	} else {
		conn, err = l.ldapConnect()
	}

	if err != nil {
		return nil, fmt.Errorf("LDAP 链接%s:%s失败,%v", l.Server, "636", err)
	}
	defer conn.Close()

	sd_flags_control := &ControlSDFlagsOID{
		Flags: 7,
	}

	searchRequest := ldap.NewSearchRequest(l.BaseDN,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		[]ldap.Control{sd_flags_control})

	ldapSearchResult, err := conn.SearchWithPaging(searchRequest, PageSize)

	if err != nil {
		return nil, fmt.Errorf("ldap查询 filter:%s, scope:%s, attributes:%v 失败 %v", filter, l.BaseDN, attributes, err)
	}
	return ldapSearchResult.Entries, nil
}

// LDAP 分页处理
func (l *LdapServer) PageSearchHandler(filter string, attributes []string, pagingSize uint32, control_server string, handler func(entry *ldap.Entry, control_server string)) error {
	var pagingControl *ldap.ControlPaging
	var conn *ldap.Conn
	var err error
	if l.SSL {
		conn, err = l.ldapTlsConnect()
	} else {
		conn, err = l.ldapConnect()
	}

	if err != nil {
		return fmt.Errorf("LDAP 链接%s:%s失败,%v", l.Server, "636", err)
	}
	defer conn.Close()

	sd_flags_control := &ControlSDFlagsOID{
		Flags: 7,
	}

	searchRequest := ldap.NewSearchRequest(l.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		[]ldap.Control{sd_flags_control})

	control := ldap.FindControl(searchRequest.Controls, ldap.ControlTypePaging)
	if control == nil {
		pagingControl = ldap.NewControlPaging(pagingSize)
		searchRequest.Controls = append(searchRequest.Controls, pagingControl)
	} else {
		castControl, ok := control.(*ldap.ControlPaging)
		if !ok {
			return fmt.Errorf("expected paging control to be of type *ControlPaging, got %v", control)
		}
		if castControl.PagingSize != pagingSize {
			return fmt.Errorf("paging size given in search request (%d) conflicts with size given in search call (%d)", castControl.PagingSize, pagingSize)
		}
		pagingControl = castControl
	}

	for {
		result, err := conn.Search(searchRequest)
		conn.Debug.Printf("Looking for Paging Control...")
		if err != nil {
			return err
		}
		if result == nil {
			return ldap.NewError(ldap.ErrorNetwork, errors.New("ldapv3: packet not received"))
		}

		for _, entry := range result.Entries {
			go handler(entry, control_server)
		}

		conn.Debug.Printf("Looking for Paging Control...")
		pagingResult := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if pagingResult == nil {
			pagingControl = nil
			conn.Debug.Printf("Could not find paging control.  Breaking...")
			break
		}

		cookie := pagingResult.(*ldap.ControlPaging).Cookie
		if len(cookie) == 0 {
			pagingControl = nil
			conn.Debug.Printf("Could not find cookie.  Breaking...")
			break
		}
		pagingControl.SetCookie(cookie)
	}

	if pagingControl != nil {
		conn.Debug.Printf("Abandoning Paging...")
		pagingControl.PagingSize = 0
		conn.Search(searchRequest)
	}

	return nil
}

// LDAP 查询机器账户
func (l *LdapServer) SearchAllComputerAccount(attributes []string, scope int) []*ldap.Entry {
	entry, err := l.PageSearch("(&(objectCategory=computer)(objectClass=computer))", attributes, 50, scope)
	if err != nil {
		// TODO: 报告异常
		return nil
	}
	return entry
}

// LDAP 查询计算机账户
func (l *LdapServer) SearchComputerAccount(cn string, attributes []string) []*ldap.Entry {
	sd_flags_control := &ControlSDFlagsOID{
		Flags: 7,
	}

	entry, err := l.Search(fmt.Sprintf("(&(objectCategory=computer)(objectClass=computer)(cn=%s))", cn), attributes, []ldap.Control{sd_flags_control})
	if err != nil {
		// TODO: 报告异常
		fmt.Println(err.Error())
		return nil
	}
	return entry
}

// LDAP 查询用户组账户
func (l *LdapServer) SearchGroupAccount(attributes []string, scope int) []*ldap.Entry {
	entry, err := l.PageSearch("(&(objectCategory=group))", attributes, 50, scope)
	if err != nil {
		// TODO: 报告异常
		return nil
	}
	return entry
}

// LDAP 查询普通用户
func (l *LdapServer) SearchUserAccount(attributes []string, scope int) []*ldap.Entry {
	entry, err := l.PageSearch("(&(objectClass=user)(objectCategory=person))", attributes, 50, scope)
	if err != nil {
		// TODO: 报告异常
		return nil
	}
	return entry
}

// LDAP 查询OU
func (l *LdapServer) SearchOU(attributes []string, scope int) []*ldap.Entry {
	entry, err := l.PageSearch("(&(objectCategory=organizationalUnit))", attributes, 50, scope)
	if err != nil {
		// TODO: 报告异常
		return nil
	}
	return entry
}

// LDAP 查询所有高价值账户
func (l *LdapServer) SearchHighRiskAccount() []*ldap.Entry {
	entry, err := l.Search("(&(objectCategory=person)(objectclass=user)(adminCount=1))", []string{"sAMAccountName"}, nil)
	if err != nil {
		// TODO: 报告异常
		fmt.Println(err.Error())
		return nil
	}
	return entry
}

// 根据SID查询用户信息
func (l *LdapServer) SearchEntryBySid(sid string, attributes []string, controls []ldap.Control) []*ldap.Entry {
	entry, err := l.Search(fmt.Sprintf("(objectSid=%s)", sid), attributes, controls)
	if err != nil {
		// TODO: 报告异常
		fmt.Println(err.Error())
		return nil
	}
	return entry
}

// 根据GUID查询用户信息
func (l *LdapServer) SearchEntryByGuid(guid []byte, attributes []string, controls []ldap.Control) []*ldap.Entry {
	guid_str := ""
	for i := 0; i < len(guid); i = i + 1 {
		guid_str += fmt.Sprintf("\\%s", hex.EncodeToString(guid[i:i+1]))
	}
	entry, err := l.Search(fmt.Sprintf("(objectGUID=%s)", guid_str), attributes, controls)

	if err != nil {
		// TODO: 报告异常
		fmt.Println(err.Error())
		return nil
	}
	return entry
}

// 查询GPO相关信息
// TODO: 冗余功能，待删除
func (l *LdapServer) SearchGPOEntry(uuid string) []*ldap.Entry {
	sd_flags_control := &ControlSDFlagsOID{
		Flags: 7,
	}
	entry, err := l.Search(fmt.Sprintf("(cn=%s)", uuid), []string{"displayName", "gPCFileSysPath", "gPCFunctionalityVersion", "nTSecurityDescriptor", "gPCFileSysPath"}, []ldap.Control{sd_flags_control})
	if err != nil {
		// TODO: 报告异常
		fmt.Println(err.Error())
		return nil
	}
	return entry
}

// 查询所有GPO对象
func (l *LdapServer) SearchAllGpo() []string {
	var gpos []string = make([]string, 0)

	entrys, err := l.Search(fmt.Sprintf("(objectCategory=%s)", "grouppolicycontainer"), []string{"cn"}, nil)
	if err != nil {
		return gpos
	}

	for _, v := range entrys {
		gpos = append(gpos, v.GetAttributeValue("cn"))
	}

	return gpos
}

// 查询nTSecurityDescriptor
func (l *LdapServer) SearchACL(filter string) []*ldap.Entry {
	sd_flags_control := &ControlSDFlagsOID{
		Flags: 7,
	}
	entry, err := l.Search(filter, []string{"nTSecurityDescriptor"}, []ldap.Control{sd_flags_control})
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return entry
}

// 根据 CN 查询
func (l *LdapServer) SearchEntryByCN(cn string, attributes []string, controls []ldap.Control) []*ldap.Entry {
	entry, err := l.Search(fmt.Sprintf("(cn=%s)", cn), attributes, controls)
	if err != nil {
		// TODO: 报告异常
		fmt.Println(err.Error())
		return nil
	}
	return entry
}

func (l *LdapServer) SearchByPrincipalName(principal_name string, attributes []string, controls []ldap.Control) []*ldap.Entry {
	entry, err := l.Search(fmt.Sprintf("(userPrincipalName=%s)", principal_name), attributes, controls)

	if err != nil {
		// TODO: 报告异常
		fmt.Println(err.Error())
		return nil
	}
	return entry
}

func (l *LdapServer) SearchEntryByDistinguishedName(distinguishedName string, attributes []string) []*ldap.Entry {
	entry, err := l.Search(fmt.Sprintf("(distinguishedName=%s)", distinguishedName), attributes, nil)

	if err != nil {
		// TODO: 报告异常
		fmt.Println(err.Error())
		return nil
	}
	return entry
}
