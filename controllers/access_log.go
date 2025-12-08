package controllers

import (
	"context"

	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/metrics"
)

// AccessLogController renders full access log page.
type AccessLogController struct {
	BaseController
}

// AccessLogViewModel holds paginated events data.
type AccessLogViewModel struct {
	MetricsEnabled  bool
	DataUnavailable bool

	Events    []metrics.AnalyticsEventRow
	Page      int
	PageSize  int
	Total     int64
	TotalPage int
	PrevPage  int
	NextPage  int
}

// NestPrepare ensures user is authenticated.
func (c *AccessLogController) NestPrepare() {
	if !c.IsLogin {
		c.Redirect(c.LoginPath(), 302)
		return
	}
}

// Get renders paginated access log entries.
func (c *AccessLogController) Get() {
	store := metrics.GetGlobalStore()
	vm := AccessLogViewModel{
		MetricsEnabled: store != nil,
	}

	c.Data["breadcrumbs"] = &BreadCrumbs{Title: "Журнал доступа"}

	if store == nil {
		c.Data["vm"] = vm
		c.TplName = "analytics/access_log.html"
		return
	}

	page, err := c.GetInt("page", 1)
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := c.GetInt("page_size", 50)
	if err != nil || pageSize <= 0 {
		pageSize = 50
	}

	ctx := context.Background()
	events, total, err := metrics.GetAccessLogPage(ctx, store, page, pageSize)
	if err != nil {
		logs.Warn("metrics: access log: %v", err)
		vm.DataUnavailable = true
	} else {
		vm.Events = events
		vm.Total = total
		vm.Page = page
		vm.PageSize = pageSize
		if total > 0 {
			vm.TotalPage = int((total + int64(pageSize) - 1) / int64(pageSize))
		} else {
			vm.TotalPage = 1
		}
		if page > 1 {
			vm.PrevPage = page - 1
		}
		if page < vm.TotalPage {
			vm.NextPage = page + 1
		}
	}

	c.Data["vm"] = vm
	c.TplName = "analytics/access_log.html"
}
