package controllers

import (
	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/lib"
)

type FirewallController struct {
	BaseController
}

func (c *FirewallController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}
	c.Data["breadcrumbs"] = &BreadCrumbs{Title: "Firewall"}
}

func (c *FirewallController) Get() {
	ctx := c.Ctx.Request.Context()
	firewallInfo, errFw := lib.CollectFirewallInfo(ctx, lib.Config{})
	if errFw != nil {
		logs.Warn("collect firewall info: %v", errFw)
	}
	if len(firewallInfo.Warnings) > 0 {
		for _, w := range firewallInfo.Warnings {
			logs.Warn("firewall warning: %s", w)
		}
	}

	c.Data["firewall"] = firewallInfo
	c.Data["metrics"] = map[string]interface{}{
		"firewall": firewallInfo,
	}

	if c.Ctx.Input.Header("Accept") == "application/json" || c.GetString("format") == "json" {
		c.Data["json"] = c.Data["metrics"]
		_ = c.ServeJSON()
		return
	}

	c.TplName = "firewall.html"
}
