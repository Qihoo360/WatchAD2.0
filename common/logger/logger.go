package logger

import (
	"path"
	"runtime"

	"github.com/sirupsen/logrus"
)

var IatpLogger = logrus.New()

func init() {
	// 设置日志格式
	IatpLogger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02 15:03:04",
		CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
			//处理文件名
			fileName := path.Base(frame.File)
			return frame.Function, fileName
		},
	})
	IatpLogger.SetReportCaller(true)
	IatpLogger.AddHook(&DetectionEngineHook{})
}
