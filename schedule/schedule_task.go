package schedule

import (
	"context"
	"iatp/common/logger"
	"iatp/schedule/domain_schedule"
	meta_data "iatp/schedule/repl_meta_data"

	"github.com/robfig/cron"
)

/*
计划任务
*/

func StartSchedule(ctx context.Context) {
	c := cron.New()

	// 注册ReplMetaData定时采集任务
	c.AddJob("@daily", meta_data.NewReplMetaData())

	// 注册域控制器列表
	c.AddJob("@weekly", domain_schedule.NewControl())

	// 万能钥匙扫描器
	c.AddJob("@daily", domain_schedule.NewSkeletonKey())

	// 动态获取域内所有高权限用户
	c.AddJob("@daily", domain_schedule.NewHighRiskUser())

	// 注册gPLink定时备份任务
	c.AddJob("@daily", domain_schedule.NewGPO())

	c.Start()

	for {
		select {
		case <-ctx.Done():
			c.Stop()
			logger.IatpLogger.Infoln("计划任务停止")
			return
		default:
			continue
		}
	}
}
