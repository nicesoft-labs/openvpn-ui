// Package routers defines application routes
// @APIVersion 1.0.0
// @Title OpenVPN API
// @Description REST API allows you to control and monitor your OpenVPN server
// @Contact adam.walach@gmail.com
// License Apache 2.0
// LicenseUrl http://www.apache.org/licenses/LICENSE-2.0.html
package routers

import (
	"net/http"

	"github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/context"
	"github.com/d3vilh/openvpn-ui/controllers"
)

func Init(configDir string, metricsHandler http.HandlerFunc) {
	web.SetStaticPath("/swagger", "swagger")
	web.Router("/", &controllers.MainController{})
	web.Router("/login", &controllers.LoginController{}, "get:Login;post:Login")
	web.Router("/logout", &controllers.LoginController{}, "get:Logout")
	web.Router("/auth/yandex", &controllers.LoginController{}, "get:YandexLogin")
	web.Router("/auth/yandex/callback", &controllers.LoginController{}, "get:YandexCallback")
	web.Router("/profile", &controllers.ProfileController{})
	web.Router("/settings", &controllers.SettingsController{})
	web.Router("/ov/config", &controllers.OVConfigController{})
	web.Router("/logs", &controllers.LogsController{})
        web.Router("/analytics", &controllers.AnalyticsController{})
        web.Router("/analytics/access-log", &controllers.AnalyticsController{}, "get:AccessLog")
	web.Router("/reports", &controllers.ReportsController{}, "get:Get")
	web.Router("/reports/download", &controllers.ReportsController{}, "post:Download")
	web.Router("/firewall", &controllers.FirewallController{})
	web.Router("/ov/clientconfig", &controllers.OVClientConfigController{ConfigDir: configDir})
	web.Router("/easyrsa/config", &controllers.EasyRSAConfigController{ConfigDir: configDir})
	web.Router("/dangerzone", &controllers.DangerController{})
	web.Router("/api/firewall/nft/snapshot", &controllers.APIFirewallNFTController{}, "get:Snapshot")

	web.Include(&controllers.CertificatesController{ConfigDir: configDir})
	web.Include(&controllers.DangerController{})
	web.Include(&controllers.OVConfigController{ConfigDir: configDir})
	web.Include(&controllers.OVClientConfigController{ConfigDir: configDir})
	web.Include(&controllers.ProfileController{})

	if metricsHandler != nil {
		web.Post("/internal/metrics/client-event", func(ctx *context.Context) {
			metricsHandler(ctx.ResponseWriter, ctx.Request)
		})
	}

	ns := web.NewNamespace("/api/v1",
		web.NSNamespace("/session",
			web.NSInclude(
				&controllers.APISessionController{},
			),
		),
		web.NSNamespace("/sysload",
			web.NSInclude(
				&controllers.APISysloadController{},
			),
		),
		web.NSNamespace("/signal",
			web.NSInclude(
				&controllers.APISignalController{},
			),
		),
	)
	web.AddNamespace(ns)
}
