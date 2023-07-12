package controllers

import (
	"fmt"
	"iatp/iatp_wbm/services"
	"strconv"
	"strings"
	"time"

	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/mvc"
	"github.com/kataras/iris/v12/sessions"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AlarmController struct {
	Ctx     iris.Context
	Service services.AlarmService
	Session *sessions.Session
}

// Method: Post
// Resiurce: /alarm/id
func (c *AlarmController) PostId() mvc.Result {
	if c.Session.Get("authenticated") == nil {
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

	id := c.Ctx.PostValue("id")
	c.Ctx.Application().Logger().Info(fmt.Sprintf("query id: %s", id))
	search_result := c.Service.GetAlarmByObjectID(id)
	if search_result == nil {
		return mvc.Response{
			Code: 404,
		}
	}

	return mvc.Response{
		ContentType: "application/json",
		Object:      c.Service.GetAlarmByObjectID(id),
	}
}

// Method: POST
// Resiurce: /alarm/search
func (c *AlarmController) PostSearch() mvc.Result {
	if c.Session.Get("authenticated") == nil {
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

	keywords := c.Ctx.PostValueDefault("keywords", "")
	alarm_level := c.Ctx.PostValueDefault("alarm_level", "")
	input_datetime_range := c.Ctx.PostValueDefault("input-datetime-range", fmt.Sprintf("%v,%v", time.Now().Add(-7*24*time.Hour).Unix(), time.Now().Unix()))
	status := c.Ctx.PostValueDefault("deal_status", "")
	picker := c.Ctx.PostValueDefault("picker", "")

	if input_datetime_range == "" {
		input_datetime_range = fmt.Sprintf("%v,%v", time.Now().Add(-7*24*time.Hour).Unix(), time.Now().Unix())
	}

	return mvc.Response{
		ContentType: "application/json",
		Object:      c.Service.GetAlarmByPage(keywords, alarm_level, input_datetime_range, status, picker),
	}
}

// Method: POST
// Resiurce: /alarm/chart
func (c *AlarmController) PostChart() mvc.Result {
	if c.Session.Get("authenticated") == nil {
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
	chart_name := c.Ctx.PostValue("chart_name")
	keywords := c.Ctx.PostValueDefault("keywords", "")
	alarm_level := c.Ctx.PostValueDefault("alarm_level", "")
	input_datetime_range := c.Ctx.PostValueDefault("input-datetime-range", fmt.Sprintf("%v,%v", time.Now().Add(-7*24*time.Hour).Unix(), time.Now().Unix()))
	status := c.Ctx.PostValueDefault("deal_status", "")
	picker := c.Ctx.PostValueDefault("picker", "")

	if input_datetime_range == "" {
		input_datetime_range = fmt.Sprintf("%v,%v", time.Now().Add(-7*24*time.Hour).Unix(), time.Now().Unix())
	}

	switch chart_name {
	case "alarm_level_chart":
		// 威胁事件等级分布
		result := c.Service.GetAlarmGroupBy(keywords, alarm_level, input_datetime_range, "$alarm_level", status, picker)

		data := make([]map[string]interface{}, 0)
		for _, v := range result {
			switch v["_id"].(string) {
			case "high":
				level := make(map[string]interface{})
				level["name"] = "高风险事件"
				level["value"] = v["count"].(int32)
				data = append(data, level)
			case "medium":
				level := make(map[string]interface{})
				level["name"] = "中风险事件"
				level["value"] = v["count"].(int32)
				data = append(data, level)
			case "information":
				level := make(map[string]interface{})
				level["name"] = "低风险事件"
				level["value"] = v["count"].(int32)
				data = append(data, level)
			}
		}

		response := map[string]interface{}{
			"code":    0,
			"message": "请求成功",
			"data": map[string]interface{}{
				"msg": data,
			},
		}

		return mvc.Response{
			Object: response,
		}
	case "alarm_count_chart":
		start_time, _ := strconv.Atoi(strings.Split(input_datetime_range, ",")[0]) // 开始时间
		end_time, _ := strconv.Atoi(strings.Split(input_datetime_range, ",")[1])   // 结束时间
		interval := (end_time - start_time) / 7

		line := make([]int32, 0)

		for i := 0; i < 7; i++ {
			result := c.Service.GetAlarmGroupBy(keywords, alarm_level, fmt.Sprintf("%v,%v", start_time+i*interval, start_time+(i+1)*interval), "", status, picker)
			if result != nil {
				line = append(line, result[0]["count"].(int32))
			}
		}

		return mvc.Response{
			Object: map[string]interface{}{
				"code":    0,
				"message": "请求成功",
				"data": map[string]interface{}{
					"line": line,
				},
			},
		}
	case "alarm_type_chart":
		result := c.Service.GetAlarmGroupBy(keywords, alarm_level, input_datetime_range, "$plugin_meta", status, picker)

		data := make([]map[string]interface{}, 0)
		for _, v := range result {
			alarm_type := make(map[string]interface{})
			alarm_type["name"] = v["_id"].(primitive.M)["systemplugin"].(primitive.M)["plugin_desc"].(string)
			alarm_type["value"] = v["count"].(int32)
			data = append(data, alarm_type)
		}

		response := map[string]interface{}{
			"code":    0,
			"message": "请求成功",
			"data": map[string]interface{}{
				"msg": data,
			},
		}

		return mvc.Response{
			Object: response,
		}
	default:
		return mvc.Response{}
	}
}

// Method: POST
// Resiurce: /alarm/flow/deal
func (c *AlarmController) PostFlowDeal() mvc.Result {
	if c.Session.Get("authenticated") == nil {
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

	select_deal := c.Ctx.PostValueDefault("select_deal", "")

	switch select_deal {
	case "alarm":
		return mvc.Response{
			Object: map[string]interface{}{
				"code":    0,
				"message": "请求成功",
				"data": map[string]int{
					"step": 2,
				},
			},
		}
	case "false_positive":
		return mvc.Response{
			Object: map[string]interface{}{
				"code":    0,
				"message": "请求成功",
				"data": map[string]int{
					"step": 3,
				},
			},
		}
	case "ignore":
		return mvc.Response{
			Object: map[string]interface{}{
				"code":    0,
				"message": "请求成功",
				"data": map[string]int{
					"step": 3,
				},
			},
		}
	default:
		return mvc.Response{
			Code: 500,
		}
	}
}

// Method: POST
// Resiurce: /alarm/flow/notice
func (c *AlarmController) PostFlowNotice() mvc.Result {
	if c.Session.Get("authenticated") == nil {
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
		Code: 200,
	}
}

// Method: POST
// Resiurce: /alarm/flow
func (c *AlarmController) PostFlow() mvc.Result {
	if c.Session.Get("authenticated") == nil {
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

	select_deal := c.Ctx.FormValueDefault("select_deal", "")
	id := c.Ctx.FormValueDefault("id", "")

	if id == "" {
		return mvc.Response{
			Code: 500,
		}
	}

	switch select_deal {
	case "false_positive":
		r := c.Service.UpdateAlarmStatus(id, "false_positive")
		if !r {
			return mvc.Response{
				Code: 500,
			}
		}
	case "ignore":
		r := c.Service.UpdateAlarmStatus(id, "ignore")
		if !r {
			return mvc.Response{
				Code: 500,
			}
		}
	case "alarm":
		r := c.Service.UpdateAlarmStatus(id, "notice")
		if !r {
			return mvc.Response{
				Code: 500,
			}
		}
	default:
		return mvc.Response{
			Code: 500,
		}
	}

	return mvc.Response{
		Code: 200,
	}
}

// Method: POST
// Resiurce: /alarm/plugin
func (c *AlarmController) PostPlugin() mvc.Result {
	if c.Session.Get("authenticated") == nil {
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

	input_datetime_range := c.Ctx.PostValueDefault("input-datetime-range", "")
	if input_datetime_range == "" {
		input_datetime_range = fmt.Sprintf("%v,%v", time.Now().Add(-7*24*time.Hour).Unix(), time.Now().Unix())
	}

	result := c.Service.GetAlarmGroupBy("", "", input_datetime_range, "$plugin_meta", "", "")

	data := make([]map[string]interface{}, 0)
	for _, v := range result {
		alarm_type := make(map[string]interface{})
		alarm_type["label"] = v["_id"].(primitive.M)["systemplugin"].(primitive.M)["plugin_desc"].(string)
		alarm_type["value"] = v["_id"].(primitive.M)["systemplugin"].(primitive.M)["plugin_name"].(string)
		data = append(data, alarm_type)
	}

	response := map[string]interface{}{
		"code":    0,
		"message": "请求成功",
		"data":    data,
	}

	return mvc.Response{
		Object: response,
	}
}

// Method: POST
// Resiurce: /alarm/raw
func (c *AlarmController) PostRaw() mvc.Result {
	if c.Session.Get("authenticated") == nil {
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

	id := c.Ctx.PostValue("id")

	response := map[string]interface{}{
		"code":    0,
		"message": "请求成功",
		"data":    c.Service.GetAlarmRawLog(id),
	}

	return mvc.Response{
		Object: response,
	}
}

// Method: POST
// Resiurce: /alarm/test
func (c *AlarmController) PostTest() mvc.Result {
	if c.Session.Get("authenticated") == nil {
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

	_select := c.Ctx.PostValueDefault("select", "")
	editor := c.Ctx.PostValueDefault("editor", "")

	return mvc.Response{
		Code:   200,
		Object: c.Service.GetAlarmTestResult(_select, editor),
	}
}
