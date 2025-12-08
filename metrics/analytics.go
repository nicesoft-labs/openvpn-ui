package metrics

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// MetricsKPI aggregates KPI counters for selected period.
type MetricsKPI struct {
	TotalSessions         int64
	ActiveSessions        int64
	UniqueUsers           int64
	UniqueCommonNames     int64
	TotalBytesIn          uint64
	TotalBytesOut         uint64
	AvgSessionDurationSec float64
	MaxConcurrentSessions int64
	PeakClients           int64
	P95Clients            float64
	P95InBps              float64
	P95OutBps             float64
	ActiveSessionsNow     int64
}

// AnalyticsDayStat represents aggregated stats per day.
type AnalyticsDayStat struct {
	Date           string
	Sessions       int64
	UniqueUsers    int64
	TotalBytes     uint64
	AvgDurationSec float64
	BytesIn        uint64
	BytesOut       uint64
}

// AnalyticsUserTraffic aggregates traffic grouped by user.
type AnalyticsUserTraffic struct {
	CommonName string
	Username   string
	Sessions   int64
	BytesIn    uint64
	BytesOut   uint64
}

// AnalyticsUserDuration aggregates duration grouped by user.
type AnalyticsUserDuration struct {
	CommonName       string
	Username         string
	Sessions         int64
	TotalDurationSec int64
}

// AnalyticsKV represents simple key/value pair.
type AnalyticsKV struct {
	Key   string
	Value int64
}

// AnalyticsSessionRow represents last sessions table row.
type AnalyticsSessionRow struct {
	SessionUID     string
	CommonName     string
	Username       string
	DeviceOS       string
	Country        string
	Cipher         string
	BytesIn        uint64
	BytesOut       uint64
	DurationSec    int64
	ConnectTime    time.Time
	DisconnectTime *time.Time
	Status         string
}

// AnalyticsEventRow represents last events table row.
type AnalyticsEventRow struct {
	EventType   string
	EventTime   time.Time
	CommonName  string
	Username    string
	TrustedIP   string
	VPNIP       string
	DeviceOS    string
	BytesIn     uint64
	BytesOut    uint64
	DurationSec int64
}

// TimePoint represents a single numeric value at timestamp.
type TimePoint struct {
	Ts  int64
	Val float64
}

// ThroughputPoint holds inbound/outbound bitrate values for timestamp.
type ThroughputPoint struct {
	Ts     int64   `json:"Ts"`
	InBps  float64 `json:"InBps"`
	OutBps float64 `json:"OutBps"`
}

// DailyTrafficPoint aggregates traffic counters by day.
type DailyTrafficPoint struct {
	Day      string
	InBytes  uint64
	OutBytes uint64
}

// TopClientPoint represents traffic usage per client.
type TopClientPoint struct {
	CommonName string
	TotalBytes uint64
}

// AnalyticsBucket groups sessions by duration bucket.
type AnalyticsBucket struct {
	Label string `json:"Label"`
	Count int64  `json:"Count"`
}

// EventsTimelinePoint holds aggregated events per time slot.
type EventsTimelinePoint struct {
	Ts          int64 `json:"Ts"`
	Connects    int64 `json:"Connects"`
	Disconnects int64 `json:"Disconnects"`
}

// MFAStats aggregates MFA usage metrics.
type MFAStats struct {
	TotalSessions int64 `json:"TotalSessions"`
	MFASessions   int64 `json:"MFASessions"`
	MFASuccess    int64 `json:"MFASuccess"`
	MFAFailed     int64 `json:"MFAFailed"`
}

// AuthMethodStat aggregates auth method usage.
type AuthMethodStat struct {
	Method string `json:"Method"`
	Count  int64  `json:"Count"`
}

// DeviceTypeStat groups devices into broad categories.
type DeviceTypeStat struct {
	Type  string `json:"Type"`
	Count int64  `json:"Count"`
}

// ClientAppStat aggregates VPN client applications used.
type ClientAppStat struct {
	App   string `json:"App"`
	Count int64  `json:"Count"`
}

// ProblemClientRow describes clients with unstable sessions.
type ProblemClientRow struct {
	CommonName     string `json:"CommonName"`
	Username       string `json:"Username"`
	Sessions       int64  `json:"Sessions"`
	Reconnects     int64  `json:"Reconnects"`
	TotalBytes     int64  `json:"TotalBytes"`
	AvgDurationSec int64  `json:"AvgDurationSec"`
	LastIP         string `json:"LastIP"`
	LastSeen       int64  `json:"LastSeen"`
}

// UsageHeatmapCell stores aggregated sessions per weekday/hour.
type UsageHeatmapCell struct {
	Weekday  int   `json:"Weekday"`
	Hour     int   `json:"Hour"`
	Sessions int64 `json:"Sessions"`
}

func getSQLDB(s Store) (*sql.DB, error) {
	switch v := s.(type) {
	case interface{ DB() *sql.DB }:
		return v.DB(), nil
	default:
		return nil, fmt.Errorf("metrics: unsupported store type %T", s)
	}
}

// AggregateSessionsKPI calculates KPI metrics for a period.
func AggregateSessionsKPI(ctx context.Context, s Store, from, to time.Time) (MetricsKPI, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return MetricsKPI{}, err
	}

	now := time.Now().UTC().Unix()
	row := db.QueryRowContext(ctx, `
SELECT
    COUNT(*) AS total_sessions,
    COALESCE(SUM(CASE WHEN status='active' THEN 1 ELSE 0 END), 0) AS active_sessions,
    COUNT(DISTINCT COALESCE(NULLIF(username, ''), common_name)) AS unique_users,
    COUNT(DISTINCT NULLIF(common_name, '')) AS unique_common_names,
    COALESCE(SUM(bytes_in), 0) AS total_bytes_in,
    COALESCE(SUM(bytes_out), 0) AS total_bytes_out,
    AVG(CASE
        WHEN duration_sec > 0 THEN duration_sec
        WHEN status='active' THEN (? - connect_time)
    END) AS avg_duration
FROM client_sessions
WHERE connect_time >= ? AND connect_time < ?;`, now, from.Unix(), to.Unix())

	var kpi MetricsKPI
	var avgDuration sql.NullFloat64
	if err := row.Scan(&kpi.TotalSessions, &kpi.ActiveSessions, &kpi.UniqueUsers, &kpi.UniqueCommonNames, &kpi.TotalBytesIn, &kpi.TotalBytesOut, &avgDuration); err != nil {
		return MetricsKPI{}, err
	}
	if avgDuration.Valid {
		kpi.AvgSessionDurationSec = avgDuration.Float64
	}

	row = db.QueryRowContext(ctx, `SELECT COALESCE(MAX(n_clients), 0) FROM mgmt_snapshots WHERE snapshot_time >= ? AND snapshot_time < ?;`, from.Unix(), to.Unix())
	if err := row.Scan(&kpi.MaxConcurrentSessions); err != nil {
		return MetricsKPI{}, err
	}

	var clients []float64
	rows, err := db.QueryContext(ctx, `SELECT n_clients FROM mgmt_snapshots WHERE snapshot_time >= ? AND snapshot_time < ? ORDER BY snapshot_time;`, from.Unix(), to.Unix())
	if err != nil {
		return MetricsKPI{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var n sql.NullInt64
		if err := rows.Scan(&n); err != nil {
			return MetricsKPI{}, err
		}
		if n.Valid {
			clients = append(clients, float64(n.Int64))
		}
	}
	if err := rows.Err(); err != nil {
		return MetricsKPI{}, err
	}

	if len(clients) > 0 {
		kpi.PeakClients = int64(maxFloat64(clients))
		kpi.P95Clients = percentileFloat64(clients, 95)
	}

	snapRows, err := db.QueryContext(ctx, `SELECT snapshot_time, bytes_in_total, bytes_out_total FROM mgmt_snapshots WHERE snapshot_time >= ? AND snapshot_time < ? ORDER BY snapshot_time;`, from.Unix(), to.Unix())
	if err != nil {
		return MetricsKPI{}, err
	}
	defer snapRows.Close()

	var snaps []throughputSnapshot
	for snapRows.Next() {
		var s throughputSnapshot
		if err := snapRows.Scan(&s.ts, &s.inTot, &s.outTot); err != nil {
			return MetricsKPI{}, err
		}
		snaps = append(snaps, s)
	}
	if err := snapRows.Err(); err != nil {
		return MetricsKPI{}, err
	}

	pts := buildThroughputFromSnapshots(snaps)
	var inVals, outVals []float64
	for _, p := range pts {
		inVals = append(inVals, p.InBps)
		outVals = append(outVals, p.OutBps)
	}
	if len(inVals) > 0 {
		kpi.P95InBps = percentileFloat64(inVals, 95)
	}
	if len(outVals) > 0 {
		kpi.P95OutBps = percentileFloat64(outVals, 95)
	}

	row = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM client_sessions WHERE status='active';`)
	if err := row.Scan(&kpi.ActiveSessionsNow); err != nil {
		return MetricsKPI{}, err
	}

	return kpi, nil
}

// AggregateSessionsByDay returns per-day aggregation for sessions.
func AggregateSessionsByDay(ctx context.Context, s Store, from, to time.Time) ([]AnalyticsDayStat, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
SELECT DATE(datetime(connect_time, 'unixepoch')) as day,
       COUNT(*) as sessions,
       COUNT(DISTINCT COALESCE(NULLIF(username, ''), common_name)) as unique_users,
       COALESCE(SUM(bytes_in + bytes_out), 0) as total_bytes,
       AVG(CASE
           WHEN duration_sec > 0 THEN duration_sec
           WHEN status='active' THEN (strftime('%s','now') - connect_time)
       END) as avg_duration,
       COALESCE(SUM(bytes_in), 0) as bytes_in,
       COALESCE(SUM(bytes_out), 0) as bytes_out
FROM client_sessions
WHERE connect_time >= ? AND connect_time < ?
GROUP BY day
ORDER BY day;
`, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []AnalyticsDayStat
	for rows.Next() {
		var st AnalyticsDayStat
		var avg sql.NullFloat64
		if err := rows.Scan(&st.Date, &st.Sessions, &st.UniqueUsers, &st.TotalBytes, &avg, &st.BytesIn, &st.BytesOut); err != nil {
			return nil, err
		}
		if avg.Valid {
			st.AvgDurationSec = avg.Float64
		}
		stats = append(stats, st)
	}
	return stats, rows.Err()
}

// AggregateTopUsersByTraffic returns users sorted by traffic.
func AggregateTopUsersByTraffic(ctx context.Context, s Store, from, to time.Time, limit int) ([]AnalyticsUserTraffic, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
SELECT common_name, username, COUNT(*) as sessions,
       COALESCE(SUM(bytes_in), 0) as bytes_in,
       COALESCE(SUM(bytes_out), 0) as bytes_out
FROM client_sessions
WHERE connect_time >= ? AND connect_time < ?
GROUP BY common_name, username
ORDER BY (COALESCE(SUM(bytes_in),0) + COALESCE(SUM(bytes_out),0)) DESC, sessions DESC
LIMIT ?;
`, from.Unix(), to.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []AnalyticsUserTraffic
	for rows.Next() {
		var it AnalyticsUserTraffic
		if err := rows.Scan(&it.CommonName, &it.Username, &it.Sessions, &it.BytesIn, &it.BytesOut); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

// AggregateTopUsersByDuration returns users sorted by duration.
func AggregateTopUsersByDuration(ctx context.Context, s Store, from, to time.Time, limit int) ([]AnalyticsUserDuration, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
SELECT common_name, username, COUNT(*) as sessions, COALESCE(SUM(duration_sec), 0) as total_duration
FROM client_sessions
WHERE connect_time >= ? AND connect_time < ?
GROUP BY common_name, username
ORDER BY total_duration DESC, sessions DESC
LIMIT ?;
`, from.Unix(), to.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []AnalyticsUserDuration
	for rows.Next() {
		var it AnalyticsUserDuration
		if err := rows.Scan(&it.CommonName, &it.Username, &it.Sessions, &it.TotalDurationSec); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

// AggregateOsDistribution returns OS distribution for sessions.
func AggregateOsDistribution(ctx context.Context, s Store, from, to time.Time) ([]AnalyticsKV, error) {
	return aggregateKV(ctx, s, from, to, "COALESCE(NULLIF(device_os, ''), 'Unknown')")
}

// AggregateCipherDistribution returns cipher distribution for sessions.
func AggregateCipherDistribution(ctx context.Context, s Store, from, to time.Time) ([]AnalyticsKV, error) {
	return aggregateKV(ctx, s, from, to, "COALESCE(NULLIF(cipher, ''), 'Unknown')")
}

// AggregateCountryDistribution returns country distribution for sessions.
func AggregateCountryDistribution(ctx context.Context, s Store, from, to time.Time) ([]AnalyticsKV, error) {
	return aggregateKV(ctx, s, from, to, "COALESCE(NULLIF(geo_country_name, ''), COALESCE(NULLIF(geo_country_code, ''), 'Unknown'))")
}

func aggregateKV(ctx context.Context, s Store, from, to time.Time, fieldExpr string) ([]AnalyticsKV, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`
SELECT %s as k, COUNT(*) as v
FROM client_sessions
WHERE connect_time >= ? AND connect_time < ?
GROUP BY k
ORDER BY v DESC;
`, fieldExpr)
	rows, err := db.QueryContext(ctx, query, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []AnalyticsKV
	for rows.Next() {
		var kv AnalyticsKV
		if err := rows.Scan(&kv.Key, &kv.Value); err != nil {
			return nil, err
		}
		items = append(items, kv)
	}
	return items, rows.Err()
}

// GetRecentSessions fetches last N sessions.
func GetRecentSessions(ctx context.Context, s Store, limit int) ([]AnalyticsSessionRow, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
SELECT session_uid, common_name, username,
       COALESCE(NULLIF(device_os, ''), 'Unknown') as device_os,
       COALESCE(NULLIF(geo_country_name, ''), COALESCE(NULLIF(geo_country_code, ''), '')) as country,
       cipher, bytes_in, bytes_out, duration_sec, connect_time, disconnect_time, status
FROM client_sessions
ORDER BY connect_time DESC
LIMIT ?;
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []AnalyticsSessionRow
	now := time.Now().UTC()
	for rows.Next() {
		var (
			row         AnalyticsSessionRow
			dConnect    int64
			dDisconnect sql.NullInt64
			dDuration   sql.NullInt64
		)
		if err := rows.Scan(&row.SessionUID, &row.CommonName, &row.Username, &row.DeviceOS, &row.Country, &row.Cipher, &row.BytesIn, &row.BytesOut, &dDuration, &dConnect, &dDisconnect, &row.Status); err != nil {
			return nil, err
		}
		if dDuration.Valid {
			row.DurationSec = dDuration.Int64
		}
		row.ConnectTime = time.Unix(dConnect, 0).UTC()
		if dDisconnect.Valid {
			tm := time.Unix(dDisconnect.Int64, 0).UTC()
			row.DisconnectTime = &tm
		}
		if row.DurationSec == 0 && !dDisconnect.Valid {
			row.DurationSec = int64(now.Sub(row.ConnectTime).Seconds())
		}
		if row.Country == "" {
			row.Country = "-"
		}
		items = append(items, row)
	}
	return items, rows.Err()
}

// GetRecentEvents fetches last N events.
func GetRecentEvents(ctx context.Context, s Store, limit int) ([]AnalyticsEventRow, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
SELECT event_type, event_time, common_name, username, trusted_ip, vpn_ip,
       COALESCE(NULLIF(device_os, ''), 'Unknown') as device_os,
       bytes_received, bytes_sent, duration_sec
FROM client_events
ORDER BY event_time DESC
LIMIT ?;
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []AnalyticsEventRow
	for rows.Next() {
		var (
			eventTime int64
			row       AnalyticsEventRow
		)
		if err := rows.Scan(&row.EventType, &eventTime, &row.CommonName, &row.Username, &row.TrustedIP, &row.VPNIP, &row.DeviceOS, &row.BytesIn, &row.BytesOut, &row.DurationSec); err != nil {
			return nil, err
		}
		row.EventTime = time.Unix(eventTime, 0).UTC()
		items = append(items, row)
	}
	return items, rows.Err()
}

// GetClientsTimeline fetches number of clients for the given range of hours.
func GetClientsTimeline(ctx context.Context, s Store, rangeHours int) ([]TimePoint, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	fromTs := time.Now().UTC().Add(-time.Duration(rangeHours) * time.Hour).Unix()
	rows, err := db.QueryContext(ctx, `
SELECT snapshot_time, n_clients
FROM mgmt_snapshots
WHERE snapshot_time >= ?
ORDER BY snapshot_time;
`, fromTs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TimePoint
	for rows.Next() {
		var (
			ts int64
			v  int64
		)
		if err := rows.Scan(&ts, &v); err != nil {
			return nil, err
		}
		points = append(points, TimePoint{Ts: ts, Val: float64(v)})
	}
	return points, rows.Err()
}

type throughputSnapshot struct {
	ts     int64
	inTot  int64
	outTot int64
}

// CalculateThroughput returns bitrate values calculated from snapshot deltas.
func CalculateThroughput(ctx context.Context, s Store, rangeHours int) ([]ThroughputPoint, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	fromTs := time.Now().UTC().Add(-time.Duration(rangeHours) * time.Hour).Unix()
	rows, err := db.QueryContext(ctx, `
SELECT snapshot_time, bytes_in_total, bytes_out_total
FROM mgmt_snapshots
WHERE snapshot_time >= ?
ORDER BY snapshot_time;
`, fromTs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snapshots []throughputSnapshot
	for rows.Next() {
		var s throughputSnapshot
		if err := rows.Scan(&s.ts, &s.inTot, &s.outTot); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return buildThroughputFromSnapshots(snapshots), nil
}

// GetDailyTraffic aggregates total traffic per day for the given window in days.
func GetDailyTraffic(ctx context.Context, s Store, days int) ([]DailyTrafficPoint, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	fromTs := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	rows, err := db.QueryContext(ctx, `
SELECT
    date(snapshot_time, 'unixepoch') AS day,
    MAX(bytes_in_total)  - MIN(bytes_in_total)  AS in_bytes,
    MAX(bytes_out_total) - MIN(bytes_out_total) AS out_bytes
FROM mgmt_snapshots
WHERE snapshot_time >= ?
GROUP BY day
ORDER BY day;
`, fromTs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []DailyTrafficPoint
	for rows.Next() {
		var (
			p        DailyTrafficPoint
			inBytes  int64
			outBytes int64
		)
		if err := rows.Scan(&p.Day, &inBytes, &outBytes); err != nil {
			return nil, err
		}
		if inBytes < 0 {
			inBytes = 0
		}
		if outBytes < 0 {
			outBytes = 0
		}
		p.InBytes = uint64(inBytes)
		p.OutBytes = uint64(outBytes)
		points = append(points, p)
	}
	return points, rows.Err()
}

// GetTopClientsByTraffic aggregates traffic per client for the given range of hours.
func GetTopClientsByTraffic(ctx context.Context, s Store, rangeHours, limit int) ([]TopClientPoint, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	fromTs := time.Now().UTC().Add(-time.Duration(rangeHours) * time.Hour).Unix()
	rows, err := db.QueryContext(ctx, `
SELECT
  json_extract(j.value, '$.CommonName') AS common_name,
  SUM(
    COALESCE(json_extract(j.value, '$.BytesReceived'), 0) +
    COALESCE(json_extract(j.value, '$.BytesSent'), 0)
  ) AS total_bytes
FROM mgmt_snapshots,
     json_each(raw_status_json, '$.ClientList') AS j
WHERE snapshot_time >= ?
GROUP BY common_name
ORDER BY total_bytes DESC
LIMIT ?;
`, fromTs, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TopClientPoint
	for rows.Next() {
		var p TopClientPoint
		if err := rows.Scan(&p.CommonName, &p.TotalBytes); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

// AggregateSessionDurationBuckets groups sessions by duration ranges.
func AggregateSessionDurationBuckets(ctx context.Context, s Store, from, to time.Time) ([]AnalyticsBucket, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `SELECT duration_sec, status, connect_time FROM client_sessions WHERE connect_time >= ? AND connect_time < ?;`, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now().UTC().Unix()
	buckets := map[string]int64{
		"< 5 минут":    0,
		"5–30 минут":   0,
		"30–120 минут": 0,
		"2–8 часов":    0,
		"8–24 часов":   0,
		"> 24 часов":   0,
	}

	for rows.Next() {
		var duration sql.NullInt64
		var status string
		var connect int64
		if err := rows.Scan(&duration, &status, &connect); err != nil {
			return nil, err
		}
		dur := duration.Int64
		if dur == 0 && strings.EqualFold(status, "active") {
			dur = now - connect
		}

		switch {
		case dur < 5*60:
			buckets["< 5 минут"]++
		case dur < 30*60:
			buckets["5–30 минут"]++
		case dur < 120*60:
			buckets["30–120 минут"]++
		case dur < 8*3600:
			buckets["2–8 часов"]++
		case dur < 24*3600:
			buckets["8–24 часов"]++
		default:
			buckets["> 24 часов"]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	order := []string{"< 5 минут", "5–30 минут", "30–120 минут", "2–8 часов", "8–24 часов", "> 24 часов"}
	var res []AnalyticsBucket
	for _, label := range order {
		res = append(res, AnalyticsBucket{Label: label, Count: buckets[label]})
	}
	return res, nil
}

// AggregateEventsTimeline aggregates connect/disconnect events by time slots.
func AggregateEventsTimeline(ctx context.Context, s Store, from, to time.Time, stepMinutes int) ([]EventsTimelinePoint, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}
	if stepMinutes <= 0 {
		stepMinutes = 60
	}

	rows, err := db.QueryContext(ctx, `
SELECT (event_time / (?*60)) as bucket, event_type, COUNT(*)
FROM client_events
WHERE event_time >= ? AND event_time < ?
GROUP BY bucket, event_type
ORDER BY bucket;
`, stepMinutes, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type bucketCount struct {
		bucket  int64
		typeStr string
		count   int64
	}

	var buckets []bucketCount
	for rows.Next() {
		var b bucketCount
		if err := rows.Scan(&b.bucket, &b.typeStr, &b.count); err != nil {
			return nil, err
		}
		buckets = append(buckets, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	slotMap := make(map[int64]*EventsTimelinePoint)
	for ts := from.Unix() / int64(stepMinutes*60) * int64(stepMinutes*60); ts < to.Unix(); ts += int64(stepMinutes * 60) {
		slotMap[ts] = &EventsTimelinePoint{Ts: ts}
	}

	for _, b := range buckets {
		ts := b.bucket * int64(stepMinutes*60)
		pt, ok := slotMap[ts]
		if !ok {
			pt = &EventsTimelinePoint{Ts: ts}
			slotMap[ts] = pt
		}
		if strings.EqualFold(b.typeStr, "connect") {
			pt.Connects += b.count
		} else if strings.EqualFold(b.typeStr, "disconnect") {
			pt.Disconnects += b.count
		}
	}

	var res []EventsTimelinePoint
	for _, pt := range slotMap {
		res = append(res, *pt)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Ts < res[j].Ts })

	return res, nil
}

// AggregateMFAStats returns MFA usage counters for sessions.
func AggregateMFAStats(ctx context.Context, s Store, from, to time.Time) (MFAStats, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return MFAStats{}, err
	}

	row := db.QueryRowContext(ctx, `
SELECT
    COUNT(*) as total_sessions,
    SUM(CASE WHEN mfa_used=1 THEN 1 ELSE 0 END) as mfa_sessions,
    SUM(CASE WHEN mfa_used=1 AND mfa_ok=1 THEN 1 ELSE 0 END) as mfa_success,
    SUM(CASE WHEN mfa_used=1 AND mfa_ok=0 THEN 1 ELSE 0 END) as mfa_failed
FROM client_sessions
WHERE connect_time >= ? AND connect_time < ?;
`, from.Unix(), to.Unix())

	var stats MFAStats
	if err := row.Scan(&stats.TotalSessions, &stats.MFASessions, &stats.MFASuccess, &stats.MFAFailed); err != nil {
		return MFAStats{}, err
	}
	return stats, nil
}

// AggregateAuthMethodStats groups sessions by authentication method.
func AggregateAuthMethodStats(ctx context.Context, s Store, from, to time.Time) ([]AuthMethodStat, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
SELECT COALESCE(NULLIF(auth_method, ''), 'unknown') as method, COUNT(*) as cnt
FROM client_sessions
WHERE connect_time >= ? AND connect_time < ?
GROUP BY method
ORDER BY cnt DESC;
`, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []AuthMethodStat
	for rows.Next() {
		var r AuthMethodStat
		if err := rows.Scan(&r.Method, &r.Count); err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, rows.Err()
}

// AggregateDeviceTypeStats groups devices into desktop/mobile/other.
func AggregateDeviceTypeStats(ctx context.Context, s Store, from, to time.Time) ([]DeviceTypeStat, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
SELECT
    CASE
        WHEN LOWER(COALESCE(device_os, '')) LIKE '%android%' OR LOWER(COALESCE(device_os, '')) LIKE '%ios%' THEN 'mobile'
        WHEN LOWER(COALESCE(device_os, '')) LIKE '%windows%' OR LOWER(COALESCE(device_os, '')) LIKE '%linux%'
             OR LOWER(COALESCE(device_os, '')) LIKE '%macos%' OR LOWER(COALESCE(device_os, '')) LIKE '%macosx%' THEN 'desktop'
        ELSE 'other'
    END as dtype,
    COUNT(*) as cnt
FROM client_sessions
WHERE connect_time >= ? AND connect_time < ?
GROUP BY dtype;
`, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []DeviceTypeStat
	for rows.Next() {
		var r DeviceTypeStat
		if err := rows.Scan(&r.Type, &r.Count); err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, rows.Err()
}

// AggregateClientAppStats returns most popular VPN client applications.
func AggregateClientAppStats(ctx context.Context, s Store, from, to time.Time, limit int) ([]ClientAppStat, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
SELECT
    CASE
        WHEN COALESCE(NULLIF(client_app, ''), '') = '' THEN 'unknown'
        WHEN COALESCE(NULLIF(client_app_ver, ''), '') = '' THEN client_app
        ELSE client_app || ' ' || client_app_ver
    END as app,
    COUNT(*) as cnt
FROM client_sessions
WHERE connect_time >= ? AND connect_time < ?
GROUP BY app
ORDER BY cnt DESC
LIMIT ?;
`, from.Unix(), to.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []ClientAppStat
	for rows.Next() {
		var r ClientAppStat
		if err := rows.Scan(&r.App, &r.Count); err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, rows.Err()
}

// AggregateProblemClients finds clients with most reconnects/short sessions.
func AggregateProblemClients(ctx context.Context, s Store, from, to time.Time, limit int) ([]ProblemClientRow, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
SELECT common_name, username, reconnects, bytes_in, bytes_out, duration_sec, last_seen, trusted_ip, status, connect_time
FROM client_sessions
WHERE connect_time >= ? AND connect_time < ?;
`, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now().UTC().Unix()
	byClient := make(map[string]*ProblemClientRow)
	for rows.Next() {
		var (
			cn, user, status, ip                                       sql.NullString
			reconnects, bytesIn, bytesOut, duration, lastSeen, connect sql.NullInt64
		)
		if err := rows.Scan(&cn, &user, &reconnects, &bytesIn, &bytesOut, &duration, &lastSeen, &ip, &status, &connect); err != nil {
			return nil, err
		}
		key := cn.String + "|" + user.String
		entry, ok := byClient[key]
		if !ok {
			entry = &ProblemClientRow{CommonName: cn.String, Username: user.String}
			byClient[key] = entry
		}
		entry.Sessions++
		entry.Reconnects += reconnects.Int64
		entry.TotalBytes += bytesIn.Int64 + bytesOut.Int64

		dur := duration.Int64
		if dur == 0 && strings.EqualFold(status.String, "active") {
			dur = now - connect.Int64
		}
		entry.AvgDurationSec += dur

		if lastSeen.Valid && lastSeen.Int64 > entry.LastSeen {
			entry.LastSeen = lastSeen.Int64
			entry.LastIP = ip.String
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var res []ProblemClientRow
	for _, v := range byClient {
		if v.Sessions > 0 {
			v.AvgDurationSec = v.AvgDurationSec / v.Sessions
		}
		res = append(res, *v)
	}

	sort.Slice(res, func(i, j int) bool {
		if res[i].Reconnects == res[j].Reconnects {
			return res[i].Sessions > res[j].Sessions
		}
		return res[i].Reconnects > res[j].Reconnects
	})

	if limit > 0 && len(res) > limit {
		res = res[:limit]
	}
	return res, nil
}

// AggregateUsageHeatmap builds weekday/hour usage matrix.
func AggregateUsageHeatmap(ctx context.Context, s Store, from, to time.Time) ([]UsageHeatmapCell, error) {
	db, err := getSQLDB(s)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `SELECT connect_time FROM client_sessions WHERE connect_time >= ? AND connect_time < ?;`, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[int]int64)
	for rows.Next() {
		var ts int64
		if err := rows.Scan(&ts); err != nil {
			return nil, err
		}
		tm := time.Unix(ts, 0).UTC()
		weekday := int(tm.Weekday()+6) % 7 // convert Sunday=0 to Monday=0..Sunday=6
		key := weekday*24 + tm.Hour()
		counts[key]++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var res []UsageHeatmapCell
	for weekday := 0; weekday < 7; weekday++ {
		for hour := 0; hour < 24; hour++ {
			idx := weekday*24 + hour
			res = append(res, UsageHeatmapCell{Weekday: weekday, Hour: hour, Sessions: counts[idx]})
		}
	}
	return res, nil
}

func buildThroughputFromSnapshots(snapshots []throughputSnapshot) []ThroughputPoint {
	var points []ThroughputPoint
	for i := 1; i < len(snapshots); i++ {
		prev := snapshots[i-1]
		curr := snapshots[i]
		deltaT := curr.ts - prev.ts
		if deltaT <= 0 {
			continue
		}

		deltaIn := curr.inTot - prev.inTot
		deltaOut := curr.outTot - prev.outTot
		if deltaIn < 0 || deltaOut < 0 {
			continue
		}

		inBps := float64(deltaIn) * 8.0 / float64(deltaT)
		outBps := float64(deltaOut) * 8.0 / float64(deltaT)

		points = append(points, ThroughputPoint{Ts: curr.ts, InBps: inBps, OutBps: outBps})
	}
	return points
}

func percentileFloat64(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	pos := (p / 100.0) * float64(len(sorted)-1)
	low := int(math.Floor(pos))
	up := int(math.Ceil(pos))
	if low == up {
		return sorted[low]
	}
	frac := pos - float64(low)
	return sorted[low] + (sorted[up]-sorted[low])*frac
}

func maxFloat64(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	max := vals[0]
	for _, v := range vals[1:] {
		if v > max {
			max = v
		}
	}
	return max
}
