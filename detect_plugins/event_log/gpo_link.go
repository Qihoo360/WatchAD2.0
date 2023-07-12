/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2021-06-11 10:15:56
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-02-10 12:48:08
 */
package system_plugin

import (
	"iatp/detect_plugins"
)

/*
查询GPO链接到敏感的站点、OU或用户

5136: 目录服务更改

过滤LDAP Attribute为 gPLink
*/

func init() {
	// detect_plugins.RegisterPlugin(5136, NewGPOLink())
}

type GpoLink struct {
	PluginName    string
	PluginDesc    string
	PluginVersion string
	PluginAuthor  string
}

func NewGPOLink() *GpoLink {
	return &GpoLink{
		PluginName:    "GPO LINK",
		PluginDesc:    "GPO异常链接",
		PluginVersion: "v1.0.0",
		PluginAuthor:  "iatp@iatp.com",
	}
}

func (g *GpoLink) Detect(event interface{}) *detect_plugins.PluginAlarm {
	return nil
}
