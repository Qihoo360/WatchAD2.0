package controllers

import (
	"encoding/json"
	"fmt"
	"iatp/common"
	"iatp/common/domain"
	"iatp/iatp_wbm/services"
	"strings"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/mvc"
	"github.com/kataras/iris/v12/sessions"
)

type SettingController struct {
	Ctx     iris.Context
	Service services.SettingService
	Session *sessions.Session
}

// Method: Post
// Resiurce: /setting/query
func (s *SettingController) PostQuery() mvc.Result {
	if s.Session.Get("authenticated") == nil {
		return mvc.Response{
			Object: map[string]interface{}{
				"status": 500,
				"msg":    "认证失效,需重新认证",
				"data": map[string]interface{}{
					"items": []map[string]interface{}{},
				},
			},
		}
	}

	setting_name := s.Ctx.PostValueDefault("name", "")

	if setting_name == "high_risk_spn" || setting_name == "vpn_segment" || setting_name == "explicit_credential_process" {
		value := s.Service.GetSettingByName(setting_name)["value"]

		if value == nil {
			return mvc.Response{
				ContentType: "application/json",
				Object: map[string]interface{}{
					"options": "",
					"value":   "",
				},
			}
		}

		var options []map[string]string = make([]map[string]string, 0)
		var op_select []string = make([]string, 0)

		for _, v := range value.(primitive.A) {
			options = append(options, map[string]string{
				"label": v.(string),
				"value": v.(string),
			})
			op_select = append(op_select, v.(string))
		}

		return mvc.Response{
			ContentType: "application/json",
			Object: map[string]interface{}{
				"options": options,
				"value":   strings.Join(op_select, ","),
			},
		}
	} else if setting_name == "ntlm_relay_white_user_segment" || setting_name == "certificate_activite" || setting_name == "high_risk_account" || setting_name == "join_domain_admin_user" || setting_name == "high_risk_ou" {
		searchRes := s.Service.GetSettingByName(setting_name)

		returnObj := map[string]interface{}{
			"type":            "editor",
			"name":            searchRes["name"].(string),
			"language":        "json",
			"size":            "md",
			"value":           searchRes["value"],
			"allowFullscreen": true,
		}

		return mvc.Response{
			ContentType: "application/json",
			Object:      returnObj,
		}

	} else if setting_name == "source" {
		// 配置采集来源
		returnObj := map[string]interface{}{
			"type":            "editor",
			"name":            "source",
			"language":        "json",
			"size":            "md",
			"value":           s.Service.GetSourceSetting(),
			"allowFullscreen": true,
		}

		return mvc.Response{
			ContentType: "application/json",
			Object:      returnObj,
		}
	} else if setting_name == "out_source" {
		// 配置采集来源
		returnObj := map[string]interface{}{
			"type":            "editor",
			"name":            "out_source",
			"language":        "json",
			"size":            "md",
			"value":           s.Service.GetOutSourceSetting(),
			"allowFullscreen": true,
		}

		return mvc.Response{
			ContentType: "application/json",
			Object:      returnObj,
		}
	} else if setting_name == "domain" {
		// 配置域名相关信息
		returnObj := map[string]interface{}{
			"type":            "editor",
			"name":            "domain",
			"language":        "json",
			"size":            "md",
			"value":           s.Service.GetDomainSetting(),
			"allowFullscreen": true,
		}

		return mvc.Response{
			ContentType: "application/json",
			Object:      returnObj,
		}
	} else {
		return mvc.Response{
			ContentType: "application/json",
			Object: map[string]interface{}{
				"status": 500,
				"msg":    fmt.Sprintf("%s 设置加载失败", setting_name),
				"data":   s.Service.GetSettingByName(setting_name),
			},
		}
	}
}

// Method: Post
// Resiurce: /setting/save
func (s *SettingController) PostSave() mvc.Result {
	if s.Session.Get("authenticated") == nil {
		return mvc.Response{
			Object: map[string]interface{}{
				"status": 500,
				"msg":    "认证失效,需重新认证",
				"data": map[string]interface{}{
					"items": []map[string]interface{}{},
				},
			},
		}
	}

	body, err := s.Ctx.GetBody()
	if err != nil {
		return mvc.Response{
			Object: map[string]interface{}{
				"status": 500,
				"msg":    "数据处理异常",
				"data":   map[string]interface{}{},
			},
		}
	}

	var postVal map[string]interface{}
	err = json.Unmarshal(body, &postVal)
	if err != nil {
		return mvc.Response{
			Object: map[string]interface{}{
				"status": 500,
				"msg":    "数据处理异常",
				"data":   map[string]interface{}{},
			},
		}
	}

	save_type := postVal["save_type"]
	switch save_type {
	case "general":
		// object 类型数据
		for _, set_item := range []string{"high_risk_account", "join_domain_admin_user", "high_risk_ou"} {
			var unmarshal_data map[string]interface{}
			if v, ok := postVal[set_item].(string); ok {
				err := json.Unmarshal([]byte(v), &unmarshal_data)
				if err == nil {
					err = s.Service.SaveSettingByName(set_item, unmarshal_data, "")
					if err != nil {
						return ErrorResp(err.Error())
					}
				} else {
					return ErrorResp(err.Error())
				}
			} else if v, ok := postVal[set_item].(map[string]interface{}); ok {
				err = s.Service.SaveSettingByName(set_item, v, "")
				if err != nil {
					return ErrorResp(err.Error())
				}
			}
		}

		// list 类型数据
		high_risk_spn := strings.Split(postVal["high_risk_spn"].(string), ",")
		err := s.Service.SaveSettingByName("high_risk_spn", high_risk_spn, "高风险SPN")
		if err != nil {
			return ErrorResp(err.Error())
		}

		// source or domain 相关配置数据
		for _, set_item := range []string{"source", "out_source", "domain"} {
			if v, ok := postVal[set_item].(string); ok {
				if set_item == "source" {
					var unmarshal_data []common.Source
					err := json.Unmarshal([]byte(v), &unmarshal_data)
					if err == nil {
						err = s.Service.SaveSourceSetting(unmarshal_data)
						if err != nil {
							return ErrorResp(err.Error())
						}
					} else {
						return ErrorResp(err.Error())
					}
				} else if set_item == "out_source" {
					var unmarshal_data common.OutSource
					err := json.Unmarshal([]byte(v), &unmarshal_data)
					if err == nil {
						err = s.Service.SaveOutSourceSetting(unmarshal_data)
						if err != nil {
							return ErrorResp(err.Error())
						}
					} else {
						return ErrorResp(err.Error())
					}
				} else if set_item == "domain" {
					var unmarshal_data []domain.Domain
					err := json.Unmarshal([]byte(v), &unmarshal_data)
					if err == nil {
						err = s.Service.SaveDomainSetting(unmarshal_data)
						if err != nil {
							return ErrorResp(err.Error())
						}
					} else {
						return ErrorResp(err.Error())
					}
				}
			} else if v, ok := postVal[set_item].([]common.Source); ok {
				err = s.Service.SaveSourceSetting(v)
				if err != nil {
					return ErrorResp(err.Error())
				}
			} else if v, ok := postVal[set_item].(common.OutSource); ok {
				err = s.Service.SaveOutSourceSetting(v)
				if err != nil {
					return ErrorResp(err.Error())
				}
			} else if v, ok := postVal[set_item].([]domain.Domain); ok {
				err = s.Service.SaveDomainSetting(v)
				if err != nil {
					return ErrorResp(err.Error())
				}
			}
		}
	case "plugin":
		vpn_segment := strings.Split(postVal["vpn_segment"].(string), ",")
		err := s.Service.SaveSettingByName("vpn_segment", vpn_segment, "NTLM Relay 插件 - 来源过滤(可以设置为VPN网段)")
		if err != nil {
			return ErrorResp(err.Error())
		}

		explicit_credential_process := strings.Split(postVal["explicit_credential_process"].(string), ",")
		err = s.Service.SaveSettingByName("explicit_credential_process", explicit_credential_process, "异常的显示凭据登录行为插件 - 可信的进程名")
		if err != nil {
			return ErrorResp(err.Error())
		}

		for _, set_item := range []string{"certificate_activite"} {
			var unmarshal_data map[string]interface{}
			if v, ok := postVal[set_item].(string); ok {
				err := json.Unmarshal([]byte(v), &unmarshal_data)
				if err == nil {
					err = s.Service.SaveSettingByName(set_item, unmarshal_data, "")
					if err != nil {
						return ErrorResp(err.Error())
					}
				} else {
					return ErrorResp(err.Error())
				}
			} else if v, ok := postVal[set_item].(map[string]interface{}); ok {
				err = s.Service.SaveSettingByName(set_item, v, "")
				if err != nil {
					return ErrorResp(err.Error())
				}
			}
		}

		for _, set_item := range []string{"ntlm_relay_white_user_segment"} {
			var unmarshal_data []map[string]interface{}
			if v, ok := postVal[set_item].(string); ok {
				err := json.Unmarshal([]byte(v), &unmarshal_data)
				if err == nil {
					err = s.Service.SaveSettingByName(set_item, unmarshal_data, "")
					if err != nil {
						return ErrorResp(err.Error())
					}
				} else {
					return ErrorResp(err.Error())
				}
			} else if v, ok := postVal[set_item].(map[string]interface{}); ok {
				err = s.Service.SaveSettingByName(set_item, v, "")
				if err != nil {
					return ErrorResp(err.Error())
				}
			}
		}

	default:
		return mvc.Response{
			Object: map[string]interface{}{
				"status": 500,
				"msg":    fmt.Sprintf("错误的设置保存类型: %s", save_type),
				"data":   map[string]interface{}{},
			},
		}
	}

	return mvc.Response{
		Code: 200,
		Object: map[string]interface{}{
			"status": 0,
			"msg":    "保存成功",
		},
	}
}

func ErrorResp(errorMsg string) mvc.Response {
	return mvc.Response{
		Object: map[string]interface{}{
			"status": 500,
			"msg":    errorMsg,
			"data":   map[string]interface{}{},
		},
	}
}
