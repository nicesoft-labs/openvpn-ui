package controllers

import (
	"context"
	"fmt"
	"net"
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

	PrevTotalSessions      int64
	PrevTotalTrafficBytes  uint64
	PrevUniqueUsers        int64
	PrevMFACoveragePercent float64

	SessionsChangePercent float64
	TrafficChangePercent  float64
	UsersChangePercent    float64
	MFACoverageChange     float64

	StrongCipherPercent float64
	LegacyCipherPercent float64

	MaxClientsConfigured   int64
	ClientsCapacityPercent float64

	PeakHourLabel    string
	PeakHourSessions int64
	PeakDayLabel     string

	TopCountries        []metrics.AnalyticsKV
	OtherCountriesCount int64
	TotalCountries      int

	HealthFlags []HealthFlag

	SessionInsights []SessionInsightRow

	AccountSharingSuspects      []AccountSharingSuspect
	AccountSharingSuspectsCount int

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

type HealthFlag struct {
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type SessionInsightRow struct {
	Username   string
	CommonName string
	DeviceOS   string
	Country    string
	Status     string

	ConnectTime time.Time
	DurationSec int64
	BytesTotal  uint64

	LastEventTime time.Time
	LastEventType string
	LastIP        string

	IsProblemClient bool
	Reconnects      int64
	AvgDurationSec  int64

	IsNight     bool
	IsWeekend   bool
	IsVeryShort bool

	IsAccountSharingSuspect bool

	RiskScore   int
	RiskLevel   string
	RiskReasons []string
}

// AccessLogViewModel represents data for the full access log view.
type AccessLogViewModel struct {
	Events     []metrics.AnalyticsEventRow
	Page       int
	PageSize   int
	Total      int64
	TotalPages int
	ShownFrom  int64
	ShownTo    int64
	PrevPage   int
	NextPage   int
	HasPrev    bool
	HasNext    bool
}

type AccountSharingSuspect struct {
	Username          string
	Sessions          int64
	DistinctCommon    int
	DistinctCountries int
	DistinctIPNets    int
	DistinctOS        int
	Score             int
	Reasons           []string
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

	var totalCiphers, strong, legacy int64
	for _, c := range vm.CipherDistribution {
		totalCiphers += c.Value
		name := strings.ToLower(c.Key)

		if strings.Contains(name, "bf-") || strings.Contains(name, "des") || strings.Contains(name, "3des") || strings.Contains(name, "rc2") || strings.Contains(name, "rc4") {
			legacy += c.Value
		} else {
			strong += c.Value
		}
	}

	if totalCiphers > 0 {
		vm.StrongCipherPercent = 100 * float64(strong) / float64(totalCiphers)
		vm.LegacyCipherPercent = 100 * float64(legacy) / float64(totalCiphers)
	}

	if len(vm.CountryDistribution) > 0 {
		vm.TotalCountries = len(vm.CountryDistribution)

		limit := 5
		if len(vm.CountryDistribution) < limit {
			limit = len(vm.CountryDistribution)
		}
		vm.TopCountries = vm.CountryDistribution[:limit]

		var sumTop, sumAll int64
		for i, c := range vm.CountryDistribution {
			sumAll += c.Value
			if i < limit {
				sumTop += c.Value
			}
		}
		vm.OtherCountriesCount = sumAll - sumTop
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

	var peakW, peakH int
	var peakVal int64
	for w := 0; w < 7; w++ {
		for h := 0; h < 24; h++ {
			v := heatmapView.Cells[w][h]
			if v > peakVal {
				peakVal = v
				peakW = w
				peakH = h
			}
		}
	}
	vm.HeatmapCalendar = heatmapView
	vm.PeakHourSessions = peakVal
	if peakVal > 0 {
		wd := heatmapView.RuWeekdaysShort[peakW]
		vm.PeakHourLabel = wd + " " + fmt.Sprintf("%02d:00–%02d:00", peakH, (peakH+1)%24)
		vm.PeakDayLabel = wd
	}

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

	periodDur := vm.To.Sub(vm.From)
	prevTo := vm.From
	prevFrom := vm.From.Add(-periodDur)

	prevKPI, err := metrics.AggregateSessionsKPI(ctx, store, prevFrom, prevTo)
	if err == nil {
		vm.PrevTotalSessions = prevKPI.TotalSessions
		vm.PrevTotalTrafficBytes = prevKPI.TotalBytesIn + prevKPI.TotalBytesOut
		vm.PrevUniqueUsers = prevKPI.UniqueUsers

		if prevKPI.TotalSessions > 0 {
			vm.SessionsChangePercent = 100 * (float64(vm.TotalSessions-prevKPI.TotalSessions) / float64(prevKPI.TotalSessions))
		}
		curBytes := vm.TotalBytesIn + vm.TotalBytesOut
		prevBytes := prevKPI.TotalBytesIn + prevKPI.TotalBytesOut
		if prevBytes > 0 {
			vm.TrafficChangePercent = 100 * (float64(curBytes-prevBytes) / float64(prevBytes))
		}
		if prevKPI.UniqueUsers > 0 {
			vm.UsersChangePercent = 100 * (float64(vm.UniqueUsers-prevKPI.UniqueUsers) / float64(prevKPI.UniqueUsers))
		}

		prevMFA, err2 := metrics.AggregateMFAStats(ctx, store, prevFrom, prevTo)
		if err2 == nil && prevMFA.TotalSessions > 0 {
			prevCover := 100 * float64(prevMFA.MFASessions) / float64(prevMFA.TotalSessions)
			vm.PrevMFACoveragePercent = prevCover
			if vm.MFACoveragePercent > 0 {
				vm.MFACoverageChange = vm.MFACoveragePercent - prevCover
			}
		}
	} else {
		logs.Warn("metrics: prev-period kpi aggregation: %v", err)
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

	probByKey := make(map[string]metrics.ProblemClientRow)
	for _, p := range vm.ProblemClients {
		key := p.CommonName + "|" + p.Username
		probByKey[key] = p
	}

	eventByKey := make(map[string]metrics.AnalyticsEventRow)
	for _, e := range vm.RecentEvents {
		key := e.CommonName + "|" + e.Username
		if old, ok := eventByKey[key]; !ok || e.EventTime.After(old.EventTime) {
			eventByKey[key] = e
		}
	}

	var insights []SessionInsightRow

	for _, s := range vm.RecentSessions {
		row := SessionInsightRow{
			CommonName:  s.CommonName,
			Username:    s.Username,
			DeviceOS:    s.DeviceOS,
			Country:     s.Country,
			Status:      s.Status,
			ConnectTime: s.ConnectTime,
			DurationSec: s.DurationSec,
			BytesTotal:  s.BytesIn + s.BytesOut,
		}

		key := s.CommonName + "|" + s.Username
		if ev, ok := eventByKey[key]; ok {
			row.LastEventTime = ev.EventTime
			row.LastEventType = ev.EventType
			row.LastIP = ev.TrustedIP
		}

		if p, ok := probByKey[key]; ok {
			row.IsProblemClient = true
			row.Reconnects = p.Reconnects
			row.AvgDurationSec = p.AvgDurationSec
		}

		loc := time.Local
		t := s.ConnectTime.In(loc)
		wd := t.Weekday()
		row.IsWeekend = wd == time.Saturday || wd == time.Sunday
		h := t.Hour()
		row.IsNight = h >= 0 && h < 6

		row.IsVeryShort = s.DurationSec > 0 && s.DurationSec < 5*60

		var score int
		var reasons []string

		if row.IsProblemClient {
			score += 2
			reasons = append(reasons, "частые переподключения/ошибки")
		}
		if row.IsVeryShort {
			score++
			reasons = append(reasons, "очень короткая сессия (<5 минут)")
		}
		if row.IsNight {
			score++
			reasons = append(reasons, "подключение ночью")
		}
		if row.IsWeekend {
			score++
			reasons = append(reasons, "подключение в выходной")
		}
		if row.Reconnects > 10 {
			score++
			reasons = append(reasons, "много reconnects")
		}

		row.RiskScore = score
		row.RiskReasons = reasons
		switch {
		case score >= 4:
			row.RiskLevel = "high"
		case score >= 2:
			row.RiskLevel = "medium"
		default:
			row.RiskLevel = "low"
		}

		insights = append(insights, row)
	}

	type accountSharingAgg struct {
		Sessions  int64
		Commons   map[string]struct{}
		Countries map[string]struct{}
		IPNets    map[string]struct{}
		OSes      map[string]struct{}
		HasNight  bool
		HasDay    bool
		FirstTime time.Time
		LastTime  time.Time
	}

	aggByUser := make(map[string]*accountSharingAgg)

	for _, s := range vm.RecentSessions {
		if s.Username == "" {
			continue
		}
		a, ok := aggByUser[s.Username]
		if !ok {
			a = &accountSharingAgg{
				Commons:   make(map[string]struct{}),
				Countries: make(map[string]struct{}),
				IPNets:    make(map[string]struct{}),
				OSes:      make(map[string]struct{}),
			}
			aggByUser[s.Username] = a
		}

		a.Sessions++
		if s.CommonName != "" {
			a.Commons[s.CommonName] = struct{}{}
		}
		if s.Country != "" {
			a.Countries[s.Country] = struct{}{}
		}
		if s.DeviceOS != "" {
			a.OSes[s.DeviceOS] = struct{}{}
		}

		ipStr := ""
		key := s.CommonName + "|" + s.Username
		if ev, ok := eventByKey[key]; ok {
			ipStr = ev.TrustedIP
		}
		if ipStr != "" {
			ip := net.ParseIP(ipStr)
			if ip != nil && ip.To4() != nil {
				b := ip.To4()
				prefix := fmt.Sprintf("%d.%d.%d", b[0], b[1], b[2])
				a.IPNets[prefix] = struct{}{}
			} else {
				a.IPNets[ipStr] = struct{}{}
			}
		}

		t := s.ConnectTime
		if a.FirstTime.IsZero() || t.Before(a.FirstTime) {
			a.FirstTime = t
		}
		if a.LastTime.IsZero() || t.After(a.LastTime) {
			a.LastTime = t
		}

		hour := t.In(time.Local).Hour()
		if hour >= 0 && hour < 6 {
			a.HasNight = true
		} else if hour >= 8 && hour <= 20 {
			a.HasDay = true
		}
	}

	var suspects []AccountSharingSuspect

	for username, a := range aggByUser {
		distinctCommon := len(a.Commons)
		distinctCountries := len(a.Countries)
		distinctIPNets := len(a.IPNets)
		distinctOS := len(a.OSes)

		var score int
		var reasons []string

		if distinctCountries >= 2 {
			score += 2
			reasons = append(reasons, "подключения из нескольких стран")
			if distinctCountries >= 3 {
				score++
				reasons = append(reasons, "подключения из 3+ стран")
			}
		}
		if distinctIPNets >= 3 {
			score += 2
			reasons = append(reasons, "подключения с разных сетей/провайдеров")
		}
		if distinctOS >= 2 {
			score++
			reasons = append(reasons, "разные ОС у одного пользователя")
		}
		if a.Sessions >= 5 {
			score++
			reasons = append(reasons, "много сессий за наблюдаемый период")
		}

		if !a.FirstTime.IsZero() && !a.LastTime.IsZero() {
			if a.LastTime.Sub(a.FirstTime) < 24*time.Hour && distinctCountries >= 2 {
				score += 2
				reasons = append(reasons, "подозрительные геопереезды в течение <24 часов")
			}
		}

		if a.HasNight && a.HasDay {
			score++
			reasons = append(reasons, "активность и ночами, и днём с разных окружений")
		}

		if score >= 4 {
			suspects = append(suspects, AccountSharingSuspect{
				Username:          username,
				Sessions:          a.Sessions,
				DistinctCommon:    distinctCommon,
				DistinctCountries: distinctCountries,
				DistinctIPNets:    distinctIPNets,
				DistinctOS:        distinctOS,
				Score:             score,
				Reasons:           reasons,
			})
		}
	}

	vm.AccountSharingSuspects = suspects
	vm.AccountSharingSuspectsCount = len(suspects)

	suspectUsernames := make(map[string]struct{})
	for _, s := range vm.AccountSharingSuspects {
		suspectUsernames[s.Username] = struct{}{}
	}

	for i := range insights {
		if _, ok := suspectUsernames[insights[i].Username]; ok {
			insights[i].IsAccountSharingSuspect = true
			insights[i].RiskScore += 2
			insights[i].RiskReasons = append(insights[i].RiskReasons, "подозрение на шаринг учётки")
			if insights[i].RiskScore >= 4 {
				insights[i].RiskLevel = "high"
			} else if insights[i].RiskScore >= 2 && insights[i].RiskLevel == "" {
				insights[i].RiskLevel = "medium"
			}
		}
	}

	vm.SessionInsights = insights

	vm.TLSAnomaliesCount = len(vm.TLSAnomalies)
	vm.ProblemClientsCount = len(vm.ProblemClients)

	severity := 0
	var msgs []string
	var flags []HealthFlag

	if vm.MFACoveragePercent < 30 {
		severity = 2
		msg := "низкое покрытие MFA (<30% сессий используют MFA)"
		msgs = append(msgs, msg)
		flags = append(flags, HealthFlag{Level: "critical", Code: "low_mfa", Message: msg})
	} else if vm.MFACoveragePercent < 70 {
		if severity < 1 {
			severity = 1
		}
		msg := "MFA включён не у всех (30–70% сессий)"
		msgs = append(msgs, msg)
		flags = append(flags, HealthFlag{Level: "warning", Code: "medium_mfa", Message: msg})
	}

	if vm.TLSAnomaliesCount > 0 {
		if vm.TLSAnomaliesCount > 20 {
			severity = 2
			msg := "много TLS ошибок за период"
			msgs = append(msgs, msg)
			flags = append(flags, HealthFlag{Level: "critical", Code: "many_tls_errors", Message: msg})
		} else {
			if severity < 1 {
				severity = 1
			}
			msg := "есть TLS предупреждения"
			msgs = append(msgs, msg)
			flags = append(flags, HealthFlag{Level: "warning", Code: "some_tls_warnings", Message: msg})
		}
	}

	if vm.ShortSessionPercent > 40 {
		if severity < 1 {
			severity = 1
		}
		msg := "большая доля коротких сессий (<5 мин)"
		msgs = append(msgs, msg)
		flags = append(flags, HealthFlag{Level: "warning", Code: "short_sessions", Message: msg})
	}

	if vm.ProblemClientsCount > 0 {
		if severity < 1 {
			severity = 1
		}
		msg := "есть проблемные клиенты (частые переподключения / ошибки)"
		msgs = append(msgs, msg)
		flags = append(flags, HealthFlag{Level: "warning", Code: "problem_clients", Message: msg})
	}

	if vm.LegacyCipherPercent > 20 {
		if severity < 1 {
			severity = 1
		}
		msg := "значительная доля сессий на устаревших шифрах"
		msgs = append(msgs, msg)
		flags = append(flags, HealthFlag{Level: "warning", Code: "legacy_ciphers", Message: msg})
	}

	if vm.ClientsCapacityPercent > 90 && vm.MaxClientsConfigured > 0 {
		severity = 2
		msg := "пиковое число клиентов близко к лимиту max-clients"
		msgs = append(msgs, msg)
		flags = append(flags, HealthFlag{Level: "critical", Code: "capacity_limit", Message: msg})
	} else if vm.ClientsCapacityPercent > 80 && vm.MaxClientsConfigured > 0 {
		if severity < 1 {
			severity = 1
		}
		msg := "пиковое число клиентов высоко относительно max-clients"
		msgs = append(msgs, msg)
		flags = append(flags, HealthFlag{Level: "warning", Code: "capacity_warning", Message: msg})
	}

	vm.HealthFlags = flags

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

// AccessLog renders a paginated list of all access events.
func (c *AnalyticsController) AccessLog() {
	if !c.IsLogin {
		c.Redirect(c.LoginPath(), 302)
		return
	}

	store := metrics.GetGlobalStore()
	if store == nil {
		// When metrics are disabled, reuse analytics page state.
		c.Data["vm"] = AccessLogViewModel{Page: 1, PageSize: 50, TotalPages: 1}
		c.Data["breadcrumbs"] = &BreadCrumbs{Title: "Analytics"}
		c.TplName = "analytics/access-log.html"
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
	total, err := metrics.CountEvents(ctx, store)
	if err != nil {
		logs.Warn("metrics: count events: %v", err)
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	offset := (page - 1) * pageSize
	events, err := metrics.GetEventsPage(ctx, store, pageSize, offset)
	if err != nil {
		logs.Warn("metrics: list events: %v", err)
	}

	var shownFrom, shownTo int64
	if total > 0 {
		shownFrom = int64(offset) + 1
		shownTo = int64(page * pageSize)
		if shownTo > total {
			shownTo = total
		}
	}

	vm := AccessLogViewModel{
		Events:     events,
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
		ShownFrom:  shownFrom,
		ShownTo:    shownTo,
		PrevPage:   page - 1,
		NextPage:   page + 1,
		HasPrev:    page > 1,
		HasNext:    page < totalPages,
	}

	c.Data["vm"] = vm
	c.Data["breadcrumbs"] = &BreadCrumbs{Title: "Analytics", Items: []BreadCrumbItem{{Title: "Журнал доступа"}}}
	c.TplName = "analytics/access-log.html"
}
