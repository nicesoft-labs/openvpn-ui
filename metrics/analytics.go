package metrics

import (
	"context"
	"database/sql"
	"fmt"
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
}

// AnalyticsDayStat represents aggregated stats per day.
type AnalyticsDayStat struct {
	Date     string
	Sessions int64
	BytesIn  uint64
	BytesOut uint64
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
	Ts     int64
	InBps  float64
	OutBps float64
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

	row := db.QueryRowContext(ctx, `
SELECT
    COUNT(*) AS total_sessions,
    COALESCE(SUM(CASE WHEN status='active' THEN 1 ELSE 0 END), 0) AS active_sessions,
    COUNT(DISTINCT NULLIF(username, '')) AS unique_users,
    COUNT(DISTINCT NULLIF(common_name, '')) AS unique_common_names,
    COALESCE(SUM(bytes_in), 0) AS total_bytes_in,
    COALESCE(SUM(bytes_out), 0) AS total_bytes_out,
    AVG(CASE WHEN disconnect_time IS NOT NULL THEN duration_sec END) AS avg_duration
FROM client_sessions
WHERE connect_time >= ? AND connect_time < ?;`, from.Unix(), to.Unix())

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
		if err := rows.Scan(&st.Date, &st.Sessions, &st.BytesIn, &st.BytesOut); err != nil {
			return nil, err
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
		)
		if err := rows.Scan(&row.SessionUID, &row.CommonName, &row.Username, &row.DeviceOS, &row.Country, &row.Cipher, &row.BytesIn, &row.BytesOut, &row.DurationSec, &dConnect, &dDisconnect, &row.Status); err != nil {
			return nil, err
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

	type snapshot struct {
		ts     int64
		inTot  int64
		outTot int64
	}

	var snapshots []snapshot
	for rows.Next() {
		var s snapshot
		if err := rows.Scan(&s.ts, &s.inTot, &s.outTot); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

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

		inBps := float64(deltaIn) * 8.0 / float64(deltaT)
		outBps := float64(deltaOut) * 8.0 / float64(deltaT)

		points = append(points, ThroughputPoint{Ts: curr.ts, InBps: inBps, OutBps: outBps})
	}

	return points, nil
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
