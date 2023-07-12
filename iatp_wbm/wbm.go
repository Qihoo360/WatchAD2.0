/*
 * @Descripttion:
 * @version:
 * @Author: daemon_zero
 * @Date: 2022-03-17 18:28:05
 * @LastEditors: daemon_zero
 * @LastEditTime: 2022-03-18 10:47:25
 */
package wbm

import (
	"iatp/iatp_wbm/controllers"
	"iatp/iatp_wbm/repositories"
	"iatp/iatp_wbm/services"
	"net"
	"time"

	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/mvc"
	"github.com/kataras/iris/v12/sessions"
)

var Session = sessions.New(sessions.Config{Cookie: "iatp_session", Expires: 12 * time.Hour})

func Run() {
	app := iris.New()

	app.Use(Session.Handler())

	// TODO 新增
	// app.RegisterView(iris.HTML("./templates", ".html"))
	app.RegisterView(iris.HTML("./iatp_wbm/templates", ".html"))
	// TODO 新增
	// app.HandleDir("/static", "./static")
	app.HandleDir("/static", "./iatp_wbm/static")
	// app.HandleDir("/#/static", "./static")

	app.Get("/", func(ctx iris.Context) {
		ctx.View("login.html")
	})
	// app.Get("/login", func(ctx iris.Context) {
	// 	ctx.View("login.html")
	// })

	app.Get("/iatp", func(ctx iris.Context) {
		ctx.View("index.html")
	})

	mvc.Configure(app.Party("/alarm"), alarm)
	mvc.Configure(app.Party("/assets"), assets)
	mvc.Configure(app.Party("/user"), user)
	mvc.Configure(app.Party("/tool"), tool)
	mvc.Configure(app.Party("/setting"), setting)
	// create any custom tcp listener, unix sock file or tls tcp listener.
	l, err := net.Listen("tcp4", "0.0.0.0:80")
	if err != nil {
		panic(err)
	}

	// use of the custom listener.
	app.Run(
		iris.Listener(l),
		// iris.Addr(":80"),
		iris.WithoutServerError(iris.ErrServerClosed),
		iris.WithOptimizations,
	)
}

func alarm(app *mvc.Application) {
	repo := repositories.NewAlarmRepository()

	alarmService := services.NewAlarmService(repo)
	app.Register(alarmService, Session.Start)

	app.Handle(new(controllers.AlarmController))
}

func assets(app *mvc.Application) {
	repo := repositories.NewAssetsRepository()

	assetsService := services.NewAssetsService(repo)
	app.Register(assetsService, Session.Start)

	app.Handle(new(controllers.AssetsController))
}

func user(app *mvc.Application) {
	repo := repositories.NewUserRepository()

	userService := services.NewUserService(repo)
	app.Register(userService, Session.Start)

	app.Handle(new(controllers.UserController))
}

func tool(app *mvc.Application) {
	toolService := services.NewToolService()
	app.Register(toolService, Session.Start)

	app.Handle(new(controllers.ToolController))
}

func setting(app *mvc.Application) {
	settingService := services.NewSettingService()
	app.Register(settingService, Session.Start)

	app.Handle(new(controllers.SettingController))
}
