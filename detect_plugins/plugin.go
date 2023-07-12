package detect_plugins

import "iatp/common/domain"

func init() {
	DetectPlugins = make(map[interface{}][]Plugin)
}

type Plugin interface {
	Detect(event interface{}) *PluginAlarm
}

var DetectPlugins map[interface{}][]Plugin

func RegisterPlugin(unique_id interface{}, plugin Plugin) {
	if _, ok := DetectPlugins[unique_id]; !ok {
		DetectPlugins[unique_id] = make([]Plugin, 0)
	}

	DetectPlugins[unique_id] = append(DetectPlugins[unique_id], plugin)
}

func GetPlugins(unique_id interface{}) []Plugin {
	if value, ok := DetectPlugins[unique_id]; ok {
		return value
	} else {
		return make([]Plugin, 0)
	}
}

type SystemPlugin struct {
	PluginName    string `json:"plugin_name" bson:"plugin_name"`
	PluginDesc    string `json:"plugin_desc" bson:"plugin_desc"`
	PluginVersion string `json:"plugin_version" bson:"plugin_version"`
	PluginAuthor  string `json:"plugin_author" bson:"plugin_author"`
}

func (s *SystemPlugin) GetUserBySid(DSName, sid string) string {
	domain, err := domain.NewDomain(DSName)
	if err != nil {
		return ""
	}
	user, _ := domain.GetDomainUserBySid(sid)
	return user
}

func (s *SystemPlugin) GetWorkStation() string {
	return ""
}
