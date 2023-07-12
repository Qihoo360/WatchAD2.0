package logger

import (
	log "github.com/sirupsen/logrus"
)

type DetectionEngineHook struct {
}

func (hook *DetectionEngineHook) Fire(entry *log.Entry) error {
	entry.Data["appName"] = "IATP Engine"
	return nil
}

func (hook *DetectionEngineHook) Levels() []log.Level {
	return log.AllLevels
}
