package controllers

import (
	"context"
	"strings"
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

	SessionsByDay          []metrics.AnalyticsDayStat
	ClientsTimeline        []metrics.TimePoint
	Throughput             []metrics.ThroughputPoint
	DailyTraffic           []metrics.DailyTrafficPoint
	TopUsersByTraffic      []metrics.AnalyticsUserTraffic
	TopUsersByDuration     []metrics.AnalyticsUserDuration
	TopClientsByTraffic    []metrics.TopClientPoint
	OsDistribution         []metrics.AnalyticsKV
	CipherDistribution     []metrics.AnalyticsKV
	CountryDistribution    []metrics.AnalyticsKV
	SessionDurationBuckets []metrics.AnalyticsBucket
	EventsTimeline         []metrics.EventsTimelinePoint
	MFAStats               metrics.MFAStats
	AuthMethods            []metrics.AuthMethodStat
	DeviceTypes            []metrics.DeviceTypeStat
	TLSIssuers             []metrics.TLSIssuerStat
	TLSCerts               []metrics.TLSCertStat
	TLSAnomalies           []metrics.TLSAnomalyRow
	MTUStats               []metrics.MTUStat
	ProtoStats             []metrics.ProtoStat
	DevTypesExtra          []metrics.DevTypeStat
	RedirectStats          []metrics.RedirectGatewayStat
	LongSessions           []metrics.HeavySessionRow
	HeavySessions          []metrics.HeavySessionRow
	ClientApps             []metrics.ClientAppStat
	ProblemClients         []metrics.ProblemClientRow
	UsageHeatmap           []metrics.UsageHeatmapCell
	HeatmapCalendar        AnalyticsHeatmapView
	RecentSessions         []metrics.AnalyticsSessionRow
	RecentEvents           []metrics.AnalyticsEventRow

	TotalTrafficBytes    uint64
	TotalTrafficGiB      float64
	AvgTrafficPerUserMB  float64
	AvgSessionsPerUser   float64
	MFACoveragePercent   float64
	MFAFailurePercent    float64
	MobileSharePercent   float64
	DesktopSharePercent  float64
	OtherSharePercent    float64
	FullTunnelPercent    float64
	SplitTunnelPercent   float64
	WeekendUsagePercent  float64
	NightUsagePercent    float64
	ShortSessionPercent  float64
	TLSAnomaliesCount    int
	ProblemClientsCount  int
	OverallHealthLevel   string
	OverallHealthMessage string
}

// AnalyticsHeatmapView holds data for calendar heatmap rendering.
type AnalyticsHeatmapView struct {
	RuWeekdaysShort []string
	Cells           [7][24]int64
	MaxValue        int64
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

	loc := time.Local
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)

	switch period {
	case "7d":
		vm.To = todayStart.Add(24 * time.Hour)
		vm.From = vm.To.AddDate(0, 0, -7)
	case "30d":
		vm.To = todayStart.Add(24 * time.Hour)
		vm.From = vm.To.AddDate(0, 0, -30)
	default:
		vm.Period = "24h"
		vm.From = todayStart
		vm.To = todayStart.Add(24 * time.Hour)
	}

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
	if vm.EventsTimeline, err = metrics.AggregateEventsTimeline(ctx, store, vm.From, vm.To, 60); err != nil {
		logs.Warn("metrics: events timeline: %v", err)
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
	if vm.SessionDurationBuckets, err = metrics.AggregateSessionDurationBuckets(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: duration buckets: %v", err)
		vm.DataUnavailable = true
	}
	if vm.MFAStats, err = metrics.AggregateMFAStats(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: mfa stats: %v", err)
		vm.DataUnavailable = true
	}
	if vm.AuthMethods, err = metrics.AggregateAuthMethodStats(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: auth methods: %v", err)
		vm.DataUnavailable = true
	}
	if vm.DeviceTypes, err = metrics.AggregateDeviceTypeStats(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: device types: %v", err)
		vm.DataUnavailable = true
	}
	if vm.TLSIssuers, err = metrics.AggregateTLSIssuerStats(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: tls issuers: %v", err)
		vm.DataUnavailable = true
	}
	if vm.TLSCerts, err = metrics.AggregateTLSCertStats(ctx, store, vm.From, vm.To, 20); err != nil {
		logs.Warn("metrics: tls certs: %v", err)
		vm.DataUnavailable = true
	}
	if vm.TLSAnomalies, err = metrics.AggregateTLSAnomalies(ctx, store, vm.From, vm.To, 50); err != nil {
		logs.Warn("metrics: tls anomalies: %v", err)
		vm.DataUnavailable = true
	}
	if vm.MTUStats, err = metrics.AggregateMTUStats(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: mtu stats: %v", err)
		vm.DataUnavailable = true
	}
	if vm.ProtoStats, err = metrics.AggregateProtoStats(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: proto stats: %v", err)
		vm.DataUnavailable = true
	}
	if vm.DevTypesExtra, err = metrics.AggregateDevTypeStats(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: devtype stats: %v", err)
		vm.DataUnavailable = true
	}
	if vm.RedirectStats, err = metrics.AggregateRedirectGatewayStats(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: redirect stats: %v", err)
		vm.DataUnavailable = true
	}
	const (
		minLongSessionDuration = 24 * 3600
		minHeavyTrafficBytes   = 10 * 1024 * 1024 * 1024 // 10 GiB
	)

	if vm.LongSessions, err = metrics.AggregateLongLivedSessions(ctx, store, vm.From, vm.To, minLongSessionDuration, 20); err != nil {
		logs.Warn("metrics: long sessions: %v", err)
		vm.DataUnavailable = true
	}
	if vm.HeavySessions, err = metrics.AggregateHeavyTrafficSessions(ctx, store, vm.From, vm.To, minHeavyTrafficBytes, 20); err != nil {
		logs.Warn("metrics: heavy sessions: %v", err)
		vm.DataUnavailable = true
	}
	if vm.ClientApps, err = metrics.AggregateClientAppStats(ctx, store, vm.From, vm.To, 10); err != nil {
		logs.Warn("metrics: client apps: %v", err)
		vm.DataUnavailable = true
	}
	if vm.ProblemClients, err = metrics.AggregateProblemClients(ctx, store, vm.From, vm.To, 10); err != nil {
		logs.Warn("metrics: problem clients: %v", err)
		vm.DataUnavailable = true
	}
	if vm.UsageHeatmap, err = metrics.AggregateUsageHeatmap(ctx, store, vm.From, vm.To); err != nil {
		logs.Warn("metrics: usage heatmap: %v", err)
		vm.DataUnavailable = true
	}

	heatmapView := AnalyticsHeatmapView{
		RuWeekdaysShort: []string{"Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"},
	}
	for _, cell := range vm.UsageHeatmap {
		if cell.Weekday < 0 || cell.Weekday >= len(heatmapView.Cells) || cell.Hour < 0 || cell.Hour >= len(heatmapView.Cells[0]) {
			continue
		}
		heatmapView.Cells[cell.Weekday][cell.Hour] += cell.Sessions
		if heatmapView.Cells[cell.Weekday][cell.Hour] > heatmapView.MaxValue {
			heatmapView.MaxValue = heatmapView.Cells[cell.Weekday][cell.Hour]
		}
	}
	vm.HeatmapCalendar = heatmapView

	totalBytes := vm.TotalBytesIn + vm.TotalBytesOut
	vm.TotalTrafficBytes = totalBytes
	vm.TotalTrafficGiB = float64(totalBytes) / (1024 * 1024 * 1024)

	if vm.UniqueUsers > 0 {
		vm.AvgTrafficPerUserMB = (float64(totalBytes) / (1024 * 1024)) / float64(vm.UniqueUsers)
		vm.AvgSessionsPerUser = float64(vm.TotalSessions) / float64(vm.UniqueUsers)
	}

	stats := vm.MFAStats
	if stats.TotalSessions > 0 {
		vm.MFACoveragePercent = 100 * float64(stats.MFASessions) / float64(stats.TotalSessions)
	}
	if stats.MFASessions > 0 {
		vm.MFAFailurePercent = 100 * float64(stats.MFAFailed) / float64(stats.MFASessions)
	}

	var totalDev, mobile, desktop, other int64
	for _, d := range vm.DeviceTypes {
		totalDev += d.Count
		switch d.Type {
		case "mobile":
			mobile += d.Count
		case "desktop":
			desktop += d.Count
		default:
			other += d.Count
		}
	}
	if totalDev > 0 {
		vm.MobileSharePercent = 100 * float64(mobile) / float64(totalDev)
		vm.DesktopSharePercent = 100 * float64(desktop) / float64(totalDev)
		vm.OtherSharePercent = 100 * float64(other) / float64(totalDev)
	}

	var totalRedirect, full, split int64
	for _, r := range vm.RedirectStats {
		totalRedirect += r.Count
		if r.Mode == "redirect-gateway" {
			full += r.Count
		} else {
			split += r.Count
		}
	}
	if totalRedirect > 0 {
		vm.FullTunnelPercent = 100 * float64(full) / float64(totalRedirect)
		vm.SplitTunnelPercent = 100 * float64(split) / float64(totalRedirect)
	}

	var totalUsage, weekendUsage, nightUsage int64
	for _, cell := range vm.UsageHeatmap {
		totalUsage += cell.Sessions
		if cell.Weekday == 5 || cell.Weekday == 6 {
			weekendUsage += cell.Sessions
		}
		if cell.Hour >= 0 && cell.Hour < 6 {
			nightUsage += cell.Sessions
		}
	}
	if totalUsage > 0 {
		vm.WeekendUsagePercent = 100 * float64(weekendUsage) / float64(totalUsage)
		vm.NightUsagePercent = 100 * float64(nightUsage) / float64(totalUsage)
	}

	var totalBuckets, shortBuckets int64
	for _, b := range vm.SessionDurationBuckets {
		totalBuckets += b.Count
		if b.Label == "< 5 минут" {
			shortBuckets += b.Count
		}
	}
	if totalBuckets > 0 {
		vm.ShortSessionPercent = 100 * float64(shortBuckets) / float64(totalBuckets)
	}

	vm.TLSAnomaliesCount = len(vm.TLSAnomalies)
	vm.ProblemClientsCount = len(vm.ProblemClients)

	severity := 0
	var msgs []string

	if vm.MFACoveragePercent < 30 {
		severity = 2
		msgs = append(msgs, "низкое покрытие MFA")
	} else if vm.MFACoveragePercent < 70 {
		if severity < 1 {
			severity = 1
		}
		msgs = append(msgs, "MFA включён не у всех")
	}

	if vm.TLSAnomaliesCount > 0 {
		if vm.TLSAnomaliesCount > 20 {
			severity = 2
			msgs = append(msgs, "много TLS ошибок")
		} else {
			if severity < 1 {
				severity = 1
			}
			msgs = append(msgs, "есть TLS предупреждения")
		}
	}

	if vm.ShortSessionPercent > 40 {
		if severity < 1 {
			severity = 1
		}
		msgs = append(msgs, "много коротких сессий (<5 мин)")
	}

	if vm.ProblemClientsCount > 0 && severity < 1 {
		severity = 1
		msgs = append(msgs, "есть проблемные клиенты")
	}

	switch severity {
	case 0:
		vm.OverallHealthLevel = "ok"
		if len(msgs) == 0 {
			vm.OverallHealthMessage = "Серьёзных проблем не обнаружено."
		} else {
			vm.OverallHealthMessage = "В целом всё хорошо, но: " + strings.Join(msgs, "; ")
		}
	case 1:
		vm.OverallHealthLevel = "warning"
		vm.OverallHealthMessage = "Есть предупреждения: " + strings.Join(msgs, "; ")
	case 2:
		vm.OverallHealthLevel = "critical"
		vm.OverallHealthMessage = "Критичные проблемы: " + strings.Join(msgs, "; ")
	}

	c.Data["vm"] = vm
	c.Data["breadcrumbs"] = &BreadCrumbs{Title: "Analytics"}
	c.TplName = "analytics/index.html"
}
