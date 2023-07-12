package controllers

import (
	"fmt"
	"iatp/iatp_wbm/services"

	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/mvc"
	"github.com/kataras/iris/v12/sessions"
)

type ToolController struct {
	Ctx     iris.Context
	Service services.ToolService
	Session *sessions.Session
}

// Method: Post
// Resiurce: /domain/list
func (t *ToolController) PostDomainList() mvc.Result {
	if t.Session.Get("authenticated") == nil {
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

	return mvc.Response{
		ContentType: "application/json",
		Object:      t.Service.GetAllDomain(),
	}
}

// Method: Post
// Resiurce: /dacl/detection
func (t *ToolController) PostDaclDetection() mvc.Result {
	if t.Session.Get("authenticated") == nil {
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

	domain_name := t.Ctx.PostValueDefault("domain_name", "")
	user_name := t.Ctx.PostValueDefault("user_name", "")
	select_status := t.Ctx.PostValueDefault("select_status", "")

	return mvc.Response{
		ContentType: "application/json",
		Object:      t.Service.DaclDetection(domain_name, user_name, select_status),
	}
}

// Method: Post
// Resiurce: /tool/domain/gpo
func (t *ToolController) PostDomainGpo() mvc.Result {
	if t.Session.Get("authenticated") == nil {
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

	return mvc.Response{
		ContentType: "application/json",
		Object:      map[string]interface{}{},
	}
}

// Method: Post
// Resiurce: /tool/gpo/list
func (t *ToolController) PostGpoList() mvc.Result {
	if t.Session.Get("authenticated") == nil {
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

	return mvc.Response{
		ContentType: "application/json",
		Object:      nil,
	}
}

// Method: Post
// Resiurce: /tool/gpo/schema
func (t *ToolController) PostGpoSchema() mvc.Result {
	if t.Session.Get("authenticated") == nil {
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

	gpo_uuid := t.Ctx.PostValueDefault("gpo_uuid", "")
	domain_name := t.Ctx.PostValueDefault("domain_name", "")

	gpo_detection_res := t.Service.GPODetection(domain_name, gpo_uuid)

	if gpo_detection_res == nil {
		return mvc.Response{
			ContentType: "application/json",
			Object:      []map[string]interface{}{},
		}
	}

	reports := gpo_detection_res.GPOThreat

	var threats []map[string]interface{} = make([]map[string]interface{}, 0)

	for _, report := range reports {
		threats = append(threats, map[string]interface{}{
			"type":   "tpl",
			"tpl":    report,
			"inline": false,
		})
	}

	return mvc.Response{
		ContentType: "application/json",
		Object: []map[string]interface{}{
			{
				"type":  "panel",
				"title": "基础信息",
				"body": []map[string]interface{}{
					{
						"type":  "property",
						"title": fmt.Sprintf("%s 属性信息", gpo_detection_res.GPOName),
						"items": []map[string]interface{}{
							{
								"label":   "管理员",
								"content": gpo_detection_res.GPOAdmin,
								"span":    1,
							},
							{
								"label":   "所属域",
								"content": gpo_detection_res.GPODomain,
								"span":    1,
							},
							{
								"label":   "版本号",
								"content": gpo_detection_res.GPOVersion,
								"span":    1,
							},
							{
								"label":   "描述",
								"content": gpo_detection_res.GPODesc,
								"span":    3,
							},
						},
						"column": 3,
						"mode":   "table",
						"source": "",
					},
				},
				"className": "Panel--primary",
			},
			{
				"type":      "panel",
				"title":     "风险提示",
				"body":      threats,
				"className": "Panel--primary",
			},
		},
	}
}
