package controllers

import (
	"context"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/metrics"
)

// AnalyticsController renders aggregated VPN metrics.
type AnalyticsController struct {
	BaseController
}

// AnalyticsViewModel contains all data for analytics view.
type AnalyticsViewModel struct {
	MetricsEnabled  bool
	DataUnavailable bool

	Period     string
	From       time.Time
	To         time.Time
	RangeHours int

	metrics.MetricsKPI

	SessionsByDay       []metrics.AnalyticsDayStat
	ClientsTimeline     []metrics.TimePoint
	Throughput          []metrics.ThroughputPoint
	DailyTraffic        []metrics.DailyTrafficPoint
	TopUsersByTraffic   []metrics.AnalyticsUserTraffic
	TopUsersByDuration  []metrics.AnalyticsUserDuration
	TopClientsByTraffic []metrics.TopClientPoint
	OsDistribution      []metrics.AnalyticsKV
	CipherDistribution  []metrics.AnalyticsKV
	CountryDistribution []metrics.AnalyticsKV
	RecentSessions      []metrics.AnalyticsSessionRow
	RecentEvents        []metrics.AnalyticsEventRow
}

// Get handles GET /analytics.
func (c *AnalyticsController) Get() {
	if !c.IsLogin {
		c.Redirect(c.LoginPath(), 302)
		return
	}

	store := metrics.GetGlobalStore()
	vm := AnalyticsViewModel{}

	if store == nil {
		vm.MetricsEnabled = false
		c.Data["vm"] = vm
		c.Data["breadcrumbs"] = &BreadCrumbs{Title: "Analytics"}
		c.TplName = "analytics/index.html"
		return
	}
	vm.MetricsEnabled = true

	period := c.GetString("period", "24h")
	vm.Period = period

	now := time.Now().UTC()
	switch period {
	case "7d":
		vm.From = now.Add(-7 * 24 * time.Hour)
	case "30d":
		vm.From = now.Add(-30 * 24 * time.Hour)
	default:
		vm.From = now.Add(-24 * time.Hour)
		vm.Period = "24h"
	}
	vm.To = now

	rangeHours, err := c.GetInt("range", 24)
	if err != nil || rangeHours <= 0 {
		rangeHours = 24
	}
	vm.RangeHours = rangeHours

	ctx := context.Background()
	kpi, err := metrics.AggregateSessionsKPI(ctx, store, vm.From, vm.To)
	if err != nil {
		logs.Warn("metrics: kpi aggregation: %v", err)
		vm.DataUnavailable = true
	} else {
		vm.MetricsKPI = kpi
	}

	if vm.DataUnavailable {
		c.Data["vm"] = vm
		c.Data["breadcrumbs"] = &BreadCrumbs{Title: "Analytics"}
		c.TplName = "analytics/index.html"
		return
	}

	if vm.SessionsByDay, err = metrics.AggregateSessionsByDay(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: sessions by day: %v", err)
		vm.DataUnavailable = true
	}
	if vm.ClientsTimeline, err = metrics.GetClientsTimeline(ctx, store, vm.RangeHours); err != nil {
		logs.Warn("metrics: clients timeline: %v", err)
		vm.DataUnavailable = true
	}
	if vm.Throughput, err = metrics.CalculateThroughput(ctx, store, vm.RangeHours); err != nil {
		logs.Warn("metrics: throughput: %v", err)
		vm.DataUnavailable = true
	}
	if vm.DailyTraffic, err = metrics.GetDailyTraffic(ctx, store, 30); err != nil {
		logs.Warn("metrics: daily traffic: %v", err)
		vm.DataUnavailable = true
	}
	if vm.TopUsersByTraffic, err = metrics.AggregateTopUsersByTraffic(ctx, store, vm.From, vm.To, 10); err != nil {
		logs.Warn("metrics: top users by traffic: %v", err)
		vm.DataUnavailable = true
	}
	if vm.TopUsersByDuration, err = metrics.AggregateTopUsersByDuration(ctx, store, vm.From, vm.To, 10); err != nil {
		logs.Warn("metrics: top users by duration: %v", err)
		vm.DataUnavailable = true
	}
	if vm.TopClientsByTraffic, err = metrics.GetTopClientsByTraffic(ctx, store, vm.RangeHours, 10); err != nil {
		logs.Warn("metrics: top clients by traffic: %v", err)
		vm.DataUnavailable = true
	}
	if vm.OsDistribution, err = metrics.AggregateOsDistribution(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: os distribution: %v", err)
		vm.DataUnavailable = true
	}
	if vm.CipherDistribution, err = metrics.AggregateCipherDistribution(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: cipher distribution: %v", err)
		vm.DataUnavailable = true
	}
	if vm.CountryDistribution, err = metrics.AggregateCountryDistribution(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: country distribution: %v", err)
		vm.DataUnavailable = true
	}
	if vm.RecentSessions, err = metrics.GetRecentSessions(ctx, store, 20); err != nil {
		logs.Warn("metrics: recent sessions: %v", err)
		vm.DataUnavailable = true
	}
	if vm.RecentEvents, err = metrics.GetRecentEvents(ctx, store, 20); err != nil {
		logs.Warn("metrics: recent events: %v", err)
		vm.DataUnavailable = true
	}

	c.Data["vm"] = vm
	c.Data["breadcrumbs"] = &BreadCrumbs{Title: "Analytics"}
	c.TplName = "analytics/index.html"
}
