package learn

var LearnMap map[interface{}][]LearnModule

func init() {
	LearnMap = make(map[interface{}][]LearnModule)
	LearnMap = map[interface{}][]LearnModule{
		4624:       make([]LearnModule, 0),
		"kerberos": make([]LearnModule, 0),
	}

	var l *Logon = NewLogon()
	LearnMap[4624] = append(LearnMap[4624], l)
}

type LearnModule interface {
	IsEndLearn() bool        // 学习结束
	Learn(interface{}) error // 学习日志
}
