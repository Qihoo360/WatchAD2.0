package services

import (
	"fmt"
	"iatp/common/domain"
	ldap_tool "iatp/common/ldap"
	"iatp/detect_plugins/module"
	"iatp/tools/sddl"
	"strings"
)

type ToolService interface {
	GetAllDomain() []Select

	// dacl 检测
	DaclDetection(domain_name string, user string, select_status string) []DaclDetectionRes

	// gpo 检测
	GPODetection(domain_name string, gpo_uuid string) *GPODetectionRes
}

type toolService struct {
}

func NewToolService() ToolService {
	return &toolService{}
}

type Select struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

func (t *toolService) GetAllDomain() []Select {
	var domains []Select = make([]Select, 0)

	for _, v := range domain.GetAllDomain() {
		domains = append(domains, Select{
			Label: fmt.Sprintf("%s域", v.NetbiosDomain),
			Value: v.NetbiosDomain,
		})
	}

	return domains
}

type DaclDetectionRes struct {
	AceType             string `json:"ace_type"`
	AceMask             string `json:"ace_mask"`
	ObjectType          string `json:"object_type"`
	InheritedObjectType string `json:"inherited_object_type"`
	Sid                 string `json:"sid"`
	Status              string `json:"status"`
}

var ace_type map[int]string = map[int]string{
	0:  "ACCESS_ALLOWED_ACE_TYPE",
	1:  "ACCESS_DENIED_ACE_TYPE",
	2:  "SYSTEM_AUDIT_ACE_TYPE",
	3:  "SYSTEM_ALARM_ACE_TYPE",
	4:  "ACCESS_ALLOWED_COMPOUND_ACE_TYPE",
	5:  "ACCESS_ALLOWED_OBJECT_ACE_TYPE",
	6:  "ACCESS_DENIED_OBJECT_ACE_TYPE",
	7:  "SYSTEM_AUDIT_OBJECT_ACE_TYPE",
	8:  "SYSTEM_ALARM_OBJECT_ACE_TYPE",
	9:  "ACCESS_ALLOWED_CALLBACK_ACE_TYPE",
	10: "ACCESS_DENIED_CALLBACK_ACE_TYPE",
	11: "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE",
	12: "ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE",
	13: "SYSTEM_AUDIT_CALLBACK_ACE_TYPE",
	14: "SYSTEM_ALARM_CALLBACK_ACE_TYPE",
	15: "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE",
	16: "SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE",
	17: "SYSTEM_MANDATORY_LABEL_ACE_TYPE",
	18: "SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE",
	19: "SYSTEM_SCOPED_POLICY_ID_ACE_TYPE",
}

var rights_map map[string]string = map[string]string{
	"GR": "Generic Read",
	"GW": "Generic Write",
	"GX": "Generic Execute",
	"GA": "Generic All",

	"WO": "Write Owner",
	"WD": "Write DAC",
	"RC": "Read Control",
	"SD": "Delete",

	"FA": "File All Access",
	"FX": "File Execute",
	"FW": "File Write",
	"FR": "File Read",

	"KA": "Key All Access",
	"KR": "Key Read",
	"KW": "Key Write",

	"CR": "Control Access",
	"LO": "List Object",
	"DT": "Delete Tree",
	"WP": "Write Property",
	"RP": "Read Property",
	"SW": "Self Write",
	"LC": "List Children",
	"DC": "Delete Child",
	"CC": "Create Child",
}

func (t *toolService) DaclDetection(domain_name string, user string, select_status string) []DaclDetectionRes {
	var res []DaclDetectionRes = make([]DaclDetectionRes, 0)
	if domain_name == "" || user == "" {
		return res
	}

	d, err := domain.NewDomain(domain_name)
	if err != nil {
		return res
	}

	ldap_client := ldap_tool.NewLdap(d.DomainServer, d.UserName, d.PassWord, d.GetDomainScope(), d.SSL)

	entrys := ldap_client.SearchACL(fmt.Sprintf("(|(cn=%s)(sAMAccountName=%s))", user, user))

	if len(entrys) == 0 {
		return res
	}

	detection := module.NewAclDetection()

	for _, ace := range sddl.NewSDDL().ReadBytes(entrys[0].GetRawAttributeValue("nTSecurityDescriptor")).Dacl.Aces {
		sid, _ := d.GetDomainUserBySid(ace.GetSid().String())
		if select_status != "" {
			if getStatus(detection, ace, d) == select_status {
				res = append(res, DaclDetectionRes{
					AceType:             ace_type[ace.GetAceType()],
					AceMask:             getRightsType(ace.GetMask()),
					ObjectType:          getObjectType(ace.GetAceObjectType()),
					InheritedObjectType: getObjectType(ace.GetAceInheritedObjectType()),
					Sid:                 sid,
					Status:              getStatus(detection, ace, d),
				})
			}
		} else {
			res = append(res, DaclDetectionRes{
				AceType:             ace_type[ace.GetAceType()],
				AceMask:             getRightsType(ace.GetMask()),
				ObjectType:          getObjectType(ace.GetAceObjectType()),
				InheritedObjectType: getObjectType(ace.GetAceInheritedObjectType()),
				Sid:                 sid,
				Status:              getStatus(detection, ace, d),
			})
		}

	}

	return res
}

func getObjectType(objectType string) string {
	if v, ok := sddl.ControlAccess[objectType]; ok {
		return v
	} else {
		return objectType
	}
}

func getRightsType(rights []string) string {
	r := make([]string, 0)
	for _, v := range rights {
		if right, ok := rights_map[v]; ok {
			r = append(r, right)
		}
	}

	return strings.Join(r, ",")
}

func getStatus(detection *module.AclDetection, ace sddl.Ace, domain *domain.Domain) string {
	if detection.Detection(ace, domain) {
		return "abnormal"
	}

	return "normal"
}

type GPODetectionRes struct {
	GPOName    string   `json:"gpo_name"`
	GPODesc    string   `json:"gpo_desc"`
	GPODomain  string   `json:"gpo_domain"`
	GPOVersion string   `json:"gpo_version"`
	GPOAdmin   string   `json:"gpo_admin"`
	GPOThreat  []string `json:"gpo_threat"`
}

func (t *toolService) GPODetection(domain_name string, gpo_uuid string) *GPODetectionRes {
	if domain_name == "" || gpo_uuid == "" {
		return nil
	}

	if !strings.HasPrefix(gpo_uuid, "{") && !strings.HasSuffix(gpo_uuid, "}") {
		gpo_uuid = fmt.Sprintf("{%s}", gpo_uuid)
	}

	d, err := domain.NewDomain(domain_name)
	if err != nil {
		return nil
	}

	ldap_client := ldap_tool.NewLdap(d.DomainServer, d.UserName, d.PassWord, d.GetDomainScope(), d.SSL)
	entrys := ldap_client.SearchGPOEntry(gpo_uuid)
	if len(entrys) < 1 {
		return nil
	}

	var owner string
	owner_entrys := ldap_client.SearchEntryBySid(sddl.NewSDDL().ReadBytes(entrys[0].GetRawAttributeValue("nTSecurityDescriptor")).Owner.String(), []string{"sAMAccountName"}, nil)
	if len(owner_entrys) > 0 {
		owner = owner_entrys[0].GetAttributeValue("sAMAccountName")
	} else {
		owner = sddl.NewSDDL().ReadBytes(entrys[0].GetRawAttributeValue("nTSecurityDescriptor")).Owner.String()
	}

	report := module.NewGPODetection().Detection(gpo_uuid, domain_name)

	if len(entrys) > 0 {
		return &GPODetectionRes{
			GPOName:    gpo_uuid,
			GPODesc:    entrys[0].GetAttributeValue("displayName"),
			GPODomain:  domain_name,
			GPOVersion: entrys[0].GetAttributeValue("gPCFunctionalityVersion"),
			GPOAdmin:   owner,
			GPOThreat:  report,
		}
	}

	return nil
}
