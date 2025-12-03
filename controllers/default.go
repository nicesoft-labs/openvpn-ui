package controllers

import (
	"context"
	"fmt"
	"net/http"
	"time"

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
		c.Ctx.Redirect(http.StatusFound, c.LoginPath())
		return
	}
	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: "NiceVPN - главная",
	}
}

func (c *MainController) Get() {
	sysinfo := lib.GetSystemInfo()

	netinfo, errNet := lib.CollectNetInfo(c.Ctx.Request.Context())
	if errNet != nil {
		logs.Warn("collect net info: %v", errNet)
	}
	for _, w := range netinfo.Warnings {
		logs.Warn("netinfo warning: %s", w)
	}

	c.Data["sysinfo"] = sysinfo
	c.Data["netinfo"] = netinfo

	// создаём MI-клиент; логируем конфиг
	client := mi.NewClient(state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress)
	logs.Info("mi client: network=%q addr=%q", state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress)

	// общий контекст с таймаутом на все MI-запросы
	ctx, cancel := context.WithTimeout(c.Ctx.Request.Context(), 3*time.Second)
	defer cancel()

	// Параллельное выполнение независимых запросов
	type res[T any] struct {
		v   T
		err error
	}

	statusCh := make(chan res[*mi.Status], 1)
	versionCh := make(chan res[*mi.Version], 1)
	pidCh := make(chan res[int], 1)
	statsCh := make(chan res[*mi.LoadStats], 1)

	go func() {
		s, err := client.GetStatusWithContext(ctx)
		if err != nil {
			statusCh <- res[*mi.Status]{v: &mi.Status{}, err: fmt.Errorf("get status: %w", err)}
			return
		}
		statusCh <- res[*mi.Status]{v: s, err: nil}
	}()

	go func() {
		v, err := client.GetVersionWithContext(ctx)
		if err != nil {
			versionCh <- res[*mi.Version]{v: &mi.Version{}, err: fmt.Errorf("get version: %w", err)}
			return
		}
		versionCh <- res[*mi.Version]{v: v, err: nil}
	}()

	go func() {
		p, err := client.GetPidWithContext(ctx)
		if err != nil {
			pidCh <- res[int]{v: 0, err: fmt.Errorf("get pid: %w", err)}
			return
		}
		pidCh <- res[int]{v: p, err: nil}
	}()

	go func() {
		ls, err := client.GetLoadStatsWithContext(ctx)
		if err != nil {
			statsCh <- res[*mi.LoadStats]{v: &mi.LoadStats{}, err: fmt.Errorf("get load stats: %w", err)}
			return
		}
		statsCh <- res[*mi.LoadStats]{v: ls, err: nil}
	}()

	statusRes := <-statusCh
	if statusRes.err != nil {
		logs.Error("%v", statusRes.err)
	}
	c.Data["ovstatus"] = statusRes.v

	versionRes := <-versionCh
	if versionRes.err != nil {
		logs.Error("%v", versionRes.err)
	}
	// приводим к строке для единообразия
	var ovVersion string
	if versionRes.v != nil && versionRes.v.OpenVPN != "" {
		ovVersion = versionRes.v.OpenVPN
	}
	c.Data["ovversion"] = ovVersion

	pidRes := <-pidCh
	if pidRes.err != nil {
		logs.Error("%v", pidRes.err)
	}
	c.Data["ovpid"] = pidRes.v

	statsRes := <-statsCh
	if statsRes.err != nil {
		logs.Error("%v", statsRes.err)
	}
	c.Data["ovstats"] = statsRes.v

	// Собираем метрики единообразно
	c.Data["metrics"] = map[string]any{
		"sysinfo":   sysinfo,
		"netinfo":   netinfo,
		"ovstatus":  statusRes.v,
		"ovversion": ovVersion,      // всегда строка
		"ovpid":     pidRes.v,       // всегда int (0 при ошибке)
		"ovstats":   statsRes.v,     // пустая структура при ошибке
	}

	c.TplName = "index.html"
}
