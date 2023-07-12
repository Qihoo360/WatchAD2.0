package module

import (
	"iatp/common/domain"
	"iatp/tools/sddl"
)

type AclDetection struct{}

func NewAclDetection() *AclDetection {
	return &AclDetection{}
}

func (d *AclDetection) Detection(ace sddl.Ace, domain *domain.Domain) (status bool) {
	if ace.GetAceType() == sddl.ACCESS_DENIED_ACE_TYPE || ace.GetAceType() == sddl.ACCESS_DENIED_OBJECT_ACE_TYPE {
		return false
	}

	sid := ace.GetSid().String()
	_, right := domain.GetDomainUserBySid(sid)

	// 非管理员用户
	if !right {
		for _, v := range ace.GetMask() {
			// 检测普通用户权限 - 普通用户权限具有...属性时触发异常
			if v == "GW" || v == "GA" || v == "WD" || v == "WO" {
				return true
			} else if v == "CR" {
				// Control Access 属性
				switch ace.GetAceObjectType() {
				// DS-Replication-Get-Changes extended right
				case "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
					return true
				// DS-Replication-Get-Changes-All extended right
				case "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":
					return true
				// DS-Replication-Get-Changes-In-Filtered-Set extended right
				case "89e95b76-444d-4c62-991a-0facbeda640c":
					return true
				// User-Force-Change-Password
				case "00299570-246d-11d0-a768-00aa006e0529":
					return true
				}
			} else if v == "WP" {
				switch ace.GetAceObjectType() {
				case "":
					return true
				case "4c164200-20c0-11d0-a768-00aa006e0529":
					return true
				case "00000000-0000-0000-0000-000000000000":
					return true
				}
			}
		}
	}
	return false
}
