/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2022-03-18 10:47:02
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-03-18 10:47:02
 */
/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2022-03-18 10:20:42
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-03-18 10:20:42
 */
package controllers

import (
	"iatp/iatp_wbm/services"

	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/mvc"
	"github.com/kataras/iris/v12/sessions"
)

type AssetsController struct {
	Ctx     iris.Context
	Service services.AssetsService
	Session *sessions.Session
}

// Method: Post
// Resiurce: /assets/detail
func (c *AssetsController) PostDetail() mvc.Result {
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

	name := c.Ctx.PostValue("name")

	search_result := c.Service.SearchByName(name)
	if search_result == nil {
		return mvc.Response{
			Code: 200,
		}
	}

	return mvc.Response{
		ContentType: "application/json",
		Object:      search_result,
	}
}
