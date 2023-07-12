package iatp

import (
	"context"
	"iatp/cache"
	"iatp/common"
	"iatp/common/database"
	"iatp/common/logger"
	decoder "iatp/decoder/event"
	"iatp/detect_plugins"
	system_plugin "iatp/detect_plugins/event_log"
	"iatp/learn"
	"iatp/schedule"
	"iatp/setting"
	"iatp/tools"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/panjf2000/ants/v2"
	log "github.com/sirupsen/logrus"
)

var wg *sync.WaitGroup

var json = jsoniter.ConfigCompatibleWithStandardLibrary
var event_pool *ants.PoolWithFunc
var learn_pool *ants.PoolWithFunc
var cache_pool *ants.PoolWithFunc

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU() - 2)
	wg = &sync.WaitGroup{}

	event_pool, _ = ants.NewPoolWithFunc(10000, func(event interface{}) {
		defer wg.Done()

		var event_id interface{}
		if event.(map[string]interface{})["event_type"].(string) == "event_log" {
			event_id = event.(map[string]interface{})["event"].(decoder.SystemEvent).WinLog.EventID
		}

		for _, plugin := range detect_plugins.GetPlugins(event_id) {
			alarm := plugin.Detect(event.(map[string]interface{})["event"])
			if alarm != nil {
				alarm.SendAlarm()
			}
		}
	})

	learn_pool, _ = ants.NewPoolWithFunc(10000, func(event interface{}) {
		defer wg.Done()

		var event_id interface{}
		if event.(map[string]interface{})["event_type"].(string) == "event_log" {
			event_id = event.(map[string]interface{})["event"].(decoder.SystemEvent).WinLog.EventID
		}

		LearnModule := learn.LearnMap[event_id]
		for _, module := range LearnModule {
			if err := module.Learn(event.(map[string]interface{})["event"]); err != nil {
				event_json, _ := json.Marshal(event.(map[string]interface{})["event"])
				log.WithFields(log.Fields{
					"module_name": reflect.TypeOf(module),
					"event":       string(event_json),
				}).Errorln(err.Error())
			}
		}
	})

	cache_pool, _ = ants.NewPoolWithFunc(10000, func(event interface{}) {
		defer wg.Done()

		var event_id interface{}
		if event.(map[string]interface{})["event_type"].(string) == "event_log" {
			event_id = event.(map[string]interface{})["event"].(decoder.SystemEvent).WinLog.EventID
		}
		if cache_handle, ok := cache.CacheEventMap[event_id]; ok {
			format_event := cache_handle.IsWriteCache(event.(map[string]interface{})["event"])
			if format_event != nil {
				cache.WriteCache(format_event, event.(map[string]interface{})["event_type"].(string))
			}
		}
	})

}

func BasicTask(engine string, msg []byte) {
	var event map[string]interface{} = make(map[string]interface{})

	switch engine {
	case "event_log":
		var system_event decoder.SystemEvent
		if err := json.Unmarshal(msg, &system_event); err != nil {
			logger.IatpLogger.WithFields(log.Fields{
				"event": string(msg),
			}).Errorf("json 解析系统日志失败: %v\n", err.Error())
		}
		event["event"] = system_event
		event["event_type"] = "event_log"
		event["msg"] = msg
	}

	if event["event"] != nil {
		// 高级威胁检测
		wg.Add(1)
		event_pool.Invoke(event)

		// 学习任务
		wg.Add(1)
		learn_pool.Invoke(event)

		//缓存事件
		wg.Add(1)
		cache_pool.Invoke(event)
	}
}

// 消息来源工作者
func sourceWorker(ctx context.Context, source common.Source) {
	defer wg.Done()
	// 检测引擎
	engine := source.SourceEngine
	source_config := source.SourceConfig

	kafkaConsumerObj := database.NewKafkaConsumerObj(source_config.Brokers, source_config.Topics,
		source_config.Version, source_config.Group, source_config.Assignor, BasicTask, engine)

	err := kafkaConsumerObj.KafkaConsumer(ctx)
	if err != nil {
		logger.IatpLogger.WithFields(
			log.Fields{
				"error":       err,
				"source_name": source.SourceName,
				"broker":      source.SourceConfig.Brokers,
				"topic":       source.SourceConfig.Topics,
				"version":     source.SourceConfig.Version,
			},
		).Errorln("kafka 消费数据异常")
	}
}

func registerBypassplugins() {
	system_plugin.RegisterPlugins()

	var plugins []string = make([]string, 0)
	for _, ps := range detect_plugins.DetectPlugins {
		for _, v := range ps {
			plugins = append(plugins, reflect.ValueOf(v).Elem().FieldByName("PluginName").String())
		}
	}
	plugins = tools.RemoveDuplicateElement(plugins)

	for _, v := range plugins {
		logger.IatpLogger.WithFields(log.Fields{
			"plugin_name": v,
		}).Infoln("加载实时日志检测插件")
	}
}

// 注册来源数据
func registerSourceEvent(ctx context.Context) {
	for _, v := range common.GetAllSourceMessageConfig() {
		logger.IatpLogger.WithFields(log.Fields{
			"source_name": v.SourceName,
		}).Infoln("数据来源启动")

		wg.Add(1)
		go sourceWorker(ctx, v)
	}
}

// 状态报告
func statusReport(ctx context.Context) {
	for {
		select {
		case <-time.NewTicker(30 * time.Minute).C:
			logger.IatpLogger.WithFields(log.Fields{"size": event_pool.Running(), "type": "event_pool"}).Infoln("日志处理池使用状态报告")
			logger.IatpLogger.WithFields(log.Fields{"size": learn_pool.Running(), "type": "learn_pool"}).Infoln("日志处理池使用状态报告")
			logger.IatpLogger.WithFields(log.Fields{"size": cache_pool.Running(), "type": "cache_pool"}).Infoln("日志处理池使用状态报告")
		case <-ctx.Done():
			return
		}
	}
}

func Start() {
	// debug.SetGCPercent(200)

	// 注册旁路检测插件
	registerBypassplugins()

	ctx, cancel := context.WithCancel(context.Background())

	wg.Add(1)
	go func() {
		defer wg.Done()
		setting.Init(ctx)
	}()
	<-setting.SettingLoad
	logger.IatpLogger.Infoln("IATP 配置加载完成")

	// 注册原始消息
	wg.Add(1)
	go func() {
		defer wg.Done()
		registerSourceEvent(ctx)
	}()

	// go func() {
	// 	http.ListenAndServe(":6060", nil)
	// }()

	// go func() {
	// 	for {
	// 		fmt.Fprintf(os.Stderr, "%d\n", runtime.NumGoroutine())
	// 		time.Sleep(10e9) //等一会，查看协程数量的变化
	// 	}
	// }()

	wg.Add(1)
	go func() {
		// 启动计划任务程序
		defer wg.Done()
		logger.IatpLogger.Infoln("计划任务服务启动完成")

		schedule.StartSchedule(ctx)
	}()

	// wg.Add(1)
	// go func() {
	// 	defer wg.Done()
	// 	wg.Add(1)
	// 	go func() {
	// 		defer wg.Done()
	// 		for {
	// 			event := <-bypass.BypassEvent
	// 			if real_time_plugin, ok := bypass.RealTimePlugins[event.MonitorDN]; ok {
	// 				alarm := real_time_plugin.Detect(event)
	// 				if alarm != nil {
	// 					alarm.SendAlarm()
	// 				}
	// 			}
	// 		}
	// 	}()

	// 	bypass.RegisterRealTimeMonitor()
	// }()

	wg.Add(1)
	go func() {
		defer wg.Done()
		statusReport(ctx)
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	cancel()

	wg.Wait()
	logger.IatpLogger.Infoln("程序执行结束")
}
