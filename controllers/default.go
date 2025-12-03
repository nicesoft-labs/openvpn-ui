package controllers

import (
	"fmt"

	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/state"
	mi "github.com/nicesoft-labs/openvpn-server-config/server/mi"
)

type MainController struct {
	BaseController
}

func (c *MainController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}
	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: "Status",
	}
}

func (c *MainController) Get() {
	sysinfo := lib.GetSystemInfo()
	// передаём контекст запроса в сборщик сетевой телеметрии
	netinfo, errNet := lib.CollectNetInfo(c.Ctx.Request.Context())
	if errNet != nil {
		logs.Warn("collect net info: %v", errNet)
	}
	// выводим предупреждения, которые твой сборщик собрал в NetInfo.Warnings
	if len(netinfo.Warnings) > 0 {
		for _, w := range netinfo.Warnings {
			logs.Warn("netinfo warning: %s", w)
		}
	}
	firewallInfo, errFw := lib.CollectFirewallInfo(c.Ctx.Request.Context(), lib.Config{})
	if errFw != nil {
		logs.Warn("collect firewall info: %v", errFw)
	}
	if len(firewallInfo.Warnings) > 0 {
		for _, w := range firewallInfo.Warnings {
			logs.Warn("firewall warning: %s", w)
		}
	}

	c.Data["sysinfo"] = sysinfo
	c.Data["netinfo"] = netinfo
	c.Data["firewall"] = firewallInfo
	lib.Dump(sysinfo)
	client := mi.NewClient(state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress)
	status, err := client.GetStatus()
	if err != nil {
		logs.Error(err)
		logs.Warn(fmt.Sprintf("passed client line: %s", client))
		logs.Warn(fmt.Sprintf("error: %s", err))
	} else {
		c.Data["ovstatus"] = status
	}
	lib.Dump(status)

	version, err := client.GetVersion()
	if err != nil {
		logs.Error(err)
	} else {
		c.Data["ovversion"] = version.OpenVPN
	}
	lib.Dump(version)

	pid, err := client.GetPid()
	if err != nil {
		logs.Error(err)
	} else {
		c.Data["ovpid"] = pid
	}
	lib.Dump(pid)

	loadStats, err := client.GetLoadStats()
	if err != nil {
		logs.Error(err)
	} else {
		c.Data["ovstats"] = loadStats
	}
	lib.Dump(loadStats)

	c.Data["metrics"] = map[string]interface{}{
		"sysinfo":   sysinfo,
		"netinfo":   netinfo,
		"ovstatus":  status,
		"ovversion": version,
		"ovpid":     pid,
		"ovstats":   loadStats,
		"firewall":  firewallInfo,
	}

	// Позволяем вернуть метрики как JSON, если запрошен API-режим.
	// Это полезно для отладки и для интеграции со сторонними дашбордами,
	// когда HTML не нужен, а нужны сами данные.
	if c.Ctx.Input.Header("Accept") == "application/json" || c.GetString("format") == "json" {
		c.Data["json"] = c.Data["metrics"]
		_ = c.ServeJSON()
		return
	}

	c.TplName = "index.html"
}
