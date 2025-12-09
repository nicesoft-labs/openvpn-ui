package metrics

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/beego/beego/v2/core/logs"
	_ "github.com/mattn/go-sqlite3"
	mi "github.com/nicesoft-labs/openvpn-server-config/server/mi"
)

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Store abstracts metrics storage backend.
type Store interface {
	InitSchema(ctx context.Context) error

	InsertClientEvent(ctx context.Context, evt *ClientEvent) error
	InsertClientEventTx(ctx context.Context, tx *sql.Tx, evt *ClientEvent) error

	UpsertSessionOnConnect(ctx context.Context, evt *ClientEvent) error
	UpsertSessionOnConnectTx(ctx context.Context, tx *sql.Tx, evt *ClientEvent) error
	UpdateSessionOnDisconnect(ctx context.Context, evt *ClientEvent) error
	UpdateSessionOnDisconnectTx(ctx context.Context, tx *sql.Tx, evt *ClientEvent) error

	UpdateSessionCryptoFromLog(ctx context.Context, cn, vpnIP, trustedIP string, trustedPort int, tlsVersion, tlsCipher, cipher, hmac string, keyBits int) error

	UpdateSessionsFromStatus(ctx context.Context, status *mi.Status) error
	InsertMgmtSnapshot(ctx context.Context, snapshotTime time.Time, status *mi.Status, stats *mi.LoadStats) error
}

// SQLiteStore implements Store using SQLite.
type SQLiteStore struct {
	db    *sql.DB
	log   *logs.BeeLogger
	debug bool
}

// NewSQLiteStore opens SQLite database with required pragmas.
func NewSQLiteStore(path string, logger *logs.BeeLogger, debug bool) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=ON")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"); err != nil {
		return nil, err
	}
	return &SQLiteStore{db: db, log: logger, debug: debug}, nil
}

// DB exposes the underlying database handle.
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

// InitSchema creates required tables if they are missing.
func (s *SQLiteStore) InitSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS client_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            event_time INTEGER NOT NULL,
            vpn_instance_id TEXT,
            common_name TEXT,
            username TEXT,
            auth_method TEXT,
            mfa_used INTEGER,
            mfa_ok INTEGER,
            trusted_ip TEXT,
            trusted_port INTEGER,
            untrusted_ip TEXT,
            untrusted_port INTEGER,
            vpn_ip TEXT,
            vpn_ipv6 TEXT,
            proto TEXT,
            dev TEXT,
            cipher TEXT,
            tls_version TEXT,
            tls_cipher TEXT,
            key_size_bits INTEGER,
            hmac_digest TEXT,
            compression TEXT,
            dco_enabled INTEGER,
            device_os TEXT,
            device_os_ver TEXT,
            device_type TEXT,
            device_vendor TEXT,
            device_model TEXT,
            device_id TEXT,
            client_app TEXT,
            client_app_ver TEXT,
            geo_country_code TEXT,
            geo_country_name TEXT,
            geo_region TEXT,
            geo_city TEXT,
            geo_asn TEXT,
            geo_org TEXT,
            geo_lat REAL,
            geo_lon REAL,
            geo_timezone TEXT,
            geo_network TEXT,
            geo_flag TEXT,
            bytes_received INTEGER,
            bytes_sent INTEGER,
            packets_received INTEGER,
            packets_sent INTEGER,
            duration_sec INTEGER,
            reconnects INTEGER,
            disconnect_reason TEXT,
            env_raw TEXT,
            created_at INTEGER NOT NULL
);`,
		`CREATE INDEX IF NOT EXISTS idx_client_events_time ON client_events(event_time);`,
		`CREATE INDEX IF NOT EXISTS idx_client_events_cn_time ON client_events(common_name, event_time);`,
		`CREATE INDEX IF NOT EXISTS idx_client_events_vpnip_time ON client_events(vpn_ip, event_time);`,
		`CREATE TABLE IF NOT EXISTS client_sessions (
    session_uid TEXT PRIMARY KEY,
    vpn_instance_id TEXT,
            common_name TEXT NOT NULL,
            username TEXT,
            department TEXT,
            user_group TEXT,
            user_role TEXT,
            trusted_ip TEXT,
            trusted_port INTEGER,
            untrusted_ip TEXT,
            untrusted_port INTEGER,
            vpn_ip TEXT,
            vpn_ipv6 TEXT,
            proto TEXT,
            dev TEXT,
            cipher TEXT,
            tls_version TEXT,
            tls_cipher TEXT,
            key_size_bits INTEGER,
            hmac_digest TEXT,
            compression TEXT,
            dco_enabled INTEGER,
            device_os TEXT,
            device_os_ver TEXT,
            device_type TEXT,
            device_vendor TEXT,
            device_model TEXT,
            device_id TEXT,
            client_app TEXT,
            client_app_ver TEXT,
            geo_country_code TEXT,
            geo_country_name TEXT,
            geo_region TEXT,
            geo_city TEXT,
            geo_asn TEXT,
            geo_org TEXT,
            geo_lat REAL,
            geo_lon REAL,
            geo_timezone TEXT,
            geo_network TEXT,
            geo_flag TEXT,
            auth_method TEXT,
            mfa_used INTEGER,
            mfa_ok INTEGER,
            is_split_tunnel INTEGER,
            is_admin_session INTEGER,
            is_external_user INTEGER,
            connect_time INTEGER NOT NULL,
            disconnect_time INTEGER,
            duration_sec INTEGER,
            last_seen INTEGER,
            bytes_in INTEGER,
            bytes_out INTEGER,
            packets_in INTEGER,
            packets_out INTEGER,
            max_bps_in INTEGER,
            max_bps_out INTEGER,
            reconnects INTEGER,
            status TEXT,
            disconnect_reason TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_client_sessions_uid ON client_sessions(session_uid);`,
		`CREATE INDEX IF NOT EXISTS idx_client_sessions_cn_time ON client_sessions(common_name, connect_time);`,
		`CREATE INDEX IF NOT EXISTS idx_client_sessions_username_time ON client_sessions(username, connect_time);`,
		`CREATE INDEX IF NOT EXISTS idx_client_sessions_status ON client_sessions(status);`,
		`CREATE TABLE IF NOT EXISTS mgmt_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_time INTEGER NOT NULL,
            n_clients INTEGER,
            bytes_in_total INTEGER,
            bytes_out_total INTEGER,
            raw_status_json TEXT
        );`,
		`CREATE INDEX IF NOT EXISTS idx_mgmt_snapshots_time ON mgmt_snapshots(snapshot_time);`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}

	columnAdditions := []struct {
		table string
		name  string
		def   string
	}{
		{"client_events", "geo_network", "geo_network TEXT"},
		{"client_events", "geo_flag", "geo_flag TEXT"},
		{"client_sessions", "geo_network", "geo_network TEXT"},
		{"client_sessions", "geo_flag", "geo_flag TEXT"},
	}

	for _, col := range columnAdditions {
		if err := s.addColumnIfMissing(ctx, col.table, col.name, col.def); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) addColumnIfMissing(ctx context.Context, table, column, columnDef string) error {
	exists, err := s.columnExists(ctx, table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", table, columnDef))
	return err
}

func (s *SQLiteStore) columnExists(ctx context.Context, table, column string) (bool, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s);", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// InsertClientEvent stores raw client event.
func (s *SQLiteStore) InsertClientEvent(ctx context.Context, evt *ClientEvent) error {
	return s.insertClientEvent(ctx, s.db, evt)
}

// InsertClientEventTx stores raw event inside provided transaction.
func (s *SQLiteStore) InsertClientEventTx(ctx context.Context, tx *sql.Tx, evt *ClientEvent) error {
	return s.insertClientEvent(ctx, tx, evt)
}

func (s *SQLiteStore) insertClientEvent(ctx context.Context, exec execer, evt *ClientEvent) error {
	_, err := exec.ExecContext(
		ctx,
		`INSERT INTO client_events (
            event_type, event_time, vpn_instance_id, common_name, username, auth_method,
            mfa_used, mfa_ok, trusted_ip, trusted_port, untrusted_ip, untrusted_port,
            vpn_ip, vpn_ipv6, proto, dev, cipher, tls_version, tls_cipher, key_size_bits,
            hmac_digest, compression, dco_enabled, device_os, device_os_ver, device_type,
            device_vendor, device_model, device_id, client_app, client_app_ver, geo_country_code,
            geo_country_name, geo_region, geo_city, geo_asn, geo_org, geo_lat, geo_lon,
            geo_timezone, geo_network, geo_flag, bytes_received, bytes_sent, packets_received, packets_sent, duration_sec,
            reconnects, disconnect_reason, env_raw, created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		evt.EventType, evt.EventTime.Unix(), evt.VPNInstanceID, evt.CommonName, evt.Username, evt.AuthMethod,
		boolToInt(evt.MFAUsed), boolToInt(evt.MFAOK), evt.TrustedIP, evt.TrustedPort, evt.UntrustedIP, evt.UntrustedPort,
		evt.VPNIP, evt.VPNIPv6, evt.Proto, evt.Dev, evt.Cipher, evt.TLSVersion, evt.TLSCipher, evt.KeySizeBits,
		evt.HMACDigest, evt.Compression, boolToInt(evt.DCOEnabled), evt.DeviceOS, evt.DeviceOSVer, evt.DeviceType,
		evt.DeviceVendor, evt.DeviceModel, evt.DeviceID, evt.ClientApp, evt.ClientAppVer, evt.GeoCountryCode,
		evt.GeoCountryName, evt.GeoRegion, evt.GeoCity, evt.GeoASN, evt.GeoOrg, evt.GeoLat, evt.GeoLon,
		evt.GeoTimezone, evt.GeoNetwork, evt.GeoFlag, evt.BytesReceived, evt.BytesSent, evt.PacketsReceived, evt.PacketsSent, evt.DurationSec,
		evt.Reconnects, evt.DisconnectReason, evt.EnvRaw, evt.CreatedAt.Unix(),
	)
	return err
}

// UpsertSessionOnConnect inserts new session for connect event or enriches existing active one.
func (s *SQLiteStore) UpsertSessionOnConnect(ctx context.Context, evt *ClientEvent) error {
	return s.upsertSessionOnConnect(ctx, s.db, evt)
}

// UpsertSessionOnConnectTx inserts or updates session inside a transaction.
func (s *SQLiteStore) UpsertSessionOnConnectTx(ctx context.Context, tx *sql.Tx, evt *ClientEvent) error {
	return s.upsertSessionOnConnect(ctx, tx, evt)
}

func (s *SQLiteStore) upsertSessionOnConnect(ctx context.Context, exec execer, evt *ClientEvent) error {
	connectTime := evt.EventTime.Unix()
	if connectTime == 0 {
		connectTime = time.Now().UTC().Unix()
	}
	sessionUID := makeSessionUID(evt.CommonName, evt.VPNIP, connectTime)
	now := time.Now().UTC().Unix()

	args := []any{
		sessionUID, evt.VPNInstanceID, evt.CommonName, evt.Username, "", "", "",
		evt.TrustedIP, evt.TrustedPort, evt.UntrustedIP, evt.UntrustedPort, evt.VPNIP, evt.VPNIPv6, evt.Proto, evt.Dev,
		evt.Cipher, evt.TLSVersion, evt.TLSCipher, evt.KeySizeBits, evt.HMACDigest, evt.Compression, boolToInt(evt.DCOEnabled),
		evt.DeviceOS, evt.DeviceOSVer, evt.DeviceType, evt.DeviceVendor, evt.DeviceModel, evt.DeviceID, evt.ClientApp, evt.ClientAppVer,
		evt.GeoCountryCode, evt.GeoCountryName, evt.GeoRegion, evt.GeoCity, evt.GeoASN, evt.GeoOrg, evt.GeoLat, evt.GeoLon, evt.GeoTimezone, evt.GeoNetwork, evt.GeoFlag,
		evt.AuthMethod, boolToInt(evt.MFAUsed), boolToInt(evt.MFAOK), 0, 0, 0,
		connectTime, nil, evt.DurationSec, connectTime, evt.BytesReceived, evt.BytesSent, evt.PacketsReceived, evt.PacketsSent,
		0, 0, evt.Reconnects, "active", evt.DisconnectReason, now, now,
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")

	_, err := exec.ExecContext(
		ctx,
		fmt.Sprintf(`INSERT INTO client_sessions (
            session_uid, vpn_instance_id, common_name, username, department, user_group, user_role,
            trusted_ip, trusted_port, untrusted_ip, untrusted_port, vpn_ip, vpn_ipv6, proto, dev,
            cipher, tls_version, tls_cipher, key_size_bits, hmac_digest, compression, dco_enabled,
            device_os, device_os_ver, device_type, device_vendor, device_model, device_id, client_app, client_app_ver,
            geo_country_code, geo_country_name, geo_region, geo_city, geo_asn, geo_org, geo_lat, geo_lon, geo_timezone, geo_network, geo_flag,
            auth_method, mfa_used, mfa_ok, is_split_tunnel, is_admin_session, is_external_user,
            connect_time, disconnect_time, duration_sec, last_seen, bytes_in, bytes_out, packets_in, packets_out,
            max_bps_in, max_bps_out, reconnects, status, disconnect_reason, created_at, updated_at
        ) VALUES (%s)
        ON CONFLICT(session_uid) DO UPDATE SET
            username=COALESCE(NULLIF(excluded.username,''), client_sessions.username),
            vpn_instance_id=COALESCE(NULLIF(excluded.vpn_instance_id,''), client_sessions.vpn_instance_id),
            trusted_ip=COALESCE(NULLIF(excluded.trusted_ip,''), client_sessions.trusted_ip),
            trusted_port=CASE WHEN excluded.trusted_port>0 THEN excluded.trusted_port ELSE client_sessions.trusted_port END,
            untrusted_ip=COALESCE(NULLIF(excluded.untrusted_ip,''), client_sessions.untrusted_ip),
            untrusted_port=CASE WHEN excluded.untrusted_port>0 THEN excluded.untrusted_port ELSE client_sessions.untrusted_port END,
            vpn_ip=COALESCE(NULLIF(excluded.vpn_ip,''), client_sessions.vpn_ip),
            vpn_ipv6=COALESCE(NULLIF(excluded.vpn_ipv6,''), client_sessions.vpn_ipv6),
            proto=COALESCE(NULLIF(excluded.proto,''), client_sessions.proto),
            dev=COALESCE(NULLIF(excluded.dev,''), client_sessions.dev),
            cipher=COALESCE(NULLIF(excluded.cipher,''), client_sessions.cipher),
            tls_version=COALESCE(NULLIF(excluded.tls_version,''), client_sessions.tls_version),
            tls_cipher=COALESCE(NULLIF(excluded.tls_cipher,''), client_sessions.tls_cipher),
            key_size_bits=CASE WHEN excluded.key_size_bits>0 THEN excluded.key_size_bits ELSE client_sessions.key_size_bits END,
            hmac_digest=COALESCE(NULLIF(excluded.hmac_digest,''), client_sessions.hmac_digest),
            compression=COALESCE(NULLIF(excluded.compression,''), client_sessions.compression),
            dco_enabled=COALESCE(excluded.dco_enabled, client_sessions.dco_enabled),
            device_os=COALESCE(NULLIF(excluded.device_os,''), client_sessions.device_os),
            device_os_ver=COALESCE(NULLIF(excluded.device_os_ver,''), client_sessions.device_os_ver),
            device_type=COALESCE(NULLIF(excluded.device_type,''), client_sessions.device_type),
            device_vendor=COALESCE(NULLIF(excluded.device_vendor,''), client_sessions.device_vendor),
            device_model=COALESCE(NULLIF(excluded.device_model,''), client_sessions.device_model),
            device_id=COALESCE(NULLIF(excluded.device_id,''), client_sessions.device_id),
            client_app=COALESCE(NULLIF(excluded.client_app,''), client_sessions.client_app),
            client_app_ver=COALESCE(NULLIF(excluded.client_app_ver,''), client_sessions.client_app_ver),
            geo_network=COALESCE(NULLIF(excluded.geo_network,''), client_sessions.geo_network),
            geo_flag=COALESCE(NULLIF(excluded.geo_flag,''), client_sessions.geo_flag),
            auth_method=COALESCE(NULLIF(excluded.auth_method,''), client_sessions.auth_method),
            mfa_used=COALESCE(excluded.mfa_used, client_sessions.mfa_used),
            mfa_ok=COALESCE(excluded.mfa_ok, client_sessions.mfa_ok),
            connect_time=COALESCE(client_sessions.connect_time, excluded.connect_time),
            disconnect_time=NULL,
            duration_sec=CASE WHEN excluded.duration_sec>0 THEN excluded.duration_sec ELSE client_sessions.duration_sec END,
            last_seen=excluded.last_seen,
            bytes_in=CASE WHEN excluded.bytes_in>0 THEN excluded.bytes_in ELSE client_sessions.bytes_in END,
            bytes_out=CASE WHEN excluded.bytes_out>0 THEN excluded.bytes_out ELSE client_sessions.bytes_out END,
            packets_in=CASE WHEN excluded.packets_in>0 THEN excluded.packets_in ELSE client_sessions.packets_in END,
            packets_out=CASE WHEN excluded.packets_out>0 THEN excluded.packets_out ELSE client_sessions.packets_out END,
            reconnects=CASE WHEN excluded.reconnects>0 THEN excluded.reconnects ELSE client_sessions.reconnects END,
            status='active',
            disconnect_reason=excluded.disconnect_reason,
            updated_at=excluded.updated_at
        ;`, placeholders),
		args...,
	)
	return err
}

// UpdateSessionOnDisconnect finalizes active session using disconnect event data.
func (s *SQLiteStore) UpdateSessionOnDisconnect(ctx context.Context, evt *ClientEvent) error {
	return s.updateSessionOnDisconnect(ctx, s.db, evt)
}

// UpdateSessionOnDisconnectTx finalizes session within a transaction.
func (s *SQLiteStore) UpdateSessionOnDisconnectTx(ctx context.Context, tx *sql.Tx, evt *ClientEvent) error {
	return s.updateSessionOnDisconnect(ctx, tx, evt)
}

func (s *SQLiteStore) updateSessionOnDisconnect(ctx context.Context, exec execer, evt *ClientEvent) error {
	q, ok := exec.(querier)
	if !ok {
		q = s.db
	}
	sessionUID, connectTime, err := s.findLatestActiveSession(ctx, q, evt.CommonName, evt.VPNIP, evt.TrustedIP, evt.TrustedPort)
	if err != nil {
		return err
	}
	if sessionUID == "" {
		return errors.New("active session not found")
	}

	duration := evt.DurationSec
	if duration == 0 && connectTime != 0 {
		duration = evt.EventTime.Unix() - connectTime
	}

	now := time.Now().UTC().Unix()
	_, err = exec.ExecContext(
		ctx,
		`UPDATE client_sessions SET disconnect_time=?, duration_sec=?, bytes_in=?, bytes_out=?, packets_in=?, packets_out=?,
            reconnects=?, status='closed', disconnect_reason=?, last_seen=?, updated_at=? WHERE session_uid=?`,
		evt.EventTime.Unix(), duration, evt.BytesReceived, evt.BytesSent, evt.PacketsReceived, evt.PacketsSent,
		evt.Reconnects, evt.DisconnectReason, evt.EventTime.Unix(), now, sessionUID,
	)
	return err
}

// UpdateSessionsFromStatus aligns session table with management interface status.
func (s *SQLiteStore) UpdateSessionsFromStatus(ctx context.Context, status *mi.Status) error {
	now := time.Now().UTC().Unix()
	if s.debug {
		s.log.Debug(
			"metrics: syncing sessions from status title=%s clients=%d routes=%d", status.Title, len(status.ClientList), len(status.RoutingTable),
		)
	}
	for _, cl := range status.ClientList {
		if cl == nil {
			continue
		}
		trustedIP, trustedPort := splitHostPort(cl.RealAddress)
		vpnIP := cl.VirtualAddress
		connectTime := parseUnix(cl.ConnectedSinceT)
		sessionUID := makeSessionUID(cl.CommonName, vpnIP, connectTime)

		_, err := s.db.ExecContext(
			ctx,
			`INSERT INTO client_sessions (
            session_uid, vpn_instance_id, common_name, username, trusted_ip, trusted_port, vpn_ip, vpn_ipv6, cipher,
            connect_time, last_seen, bytes_in, bytes_out, status, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(session_uid) DO UPDATE SET
            trusted_ip=COALESCE(NULLIF(excluded.trusted_ip,''), client_sessions.trusted_ip),
            trusted_port=CASE WHEN excluded.trusted_port>0 THEN excluded.trusted_port ELSE client_sessions.trusted_port END,
            vpn_ip=COALESCE(NULLIF(excluded.vpn_ip,''), client_sessions.vpn_ip),
            vpn_ipv6=COALESCE(NULLIF(excluded.vpn_ipv6,''), client_sessions.vpn_ipv6),
            username=COALESCE(NULLIF(excluded.username,''), client_sessions.username),
            cipher=COALESCE(NULLIF(excluded.cipher,''), client_sessions.cipher),
            bytes_in=excluded.bytes_in,
            bytes_out=excluded.bytes_out,
            last_seen=excluded.last_seen,
            status='active',
            updated_at=excluded.updated_at;`,
			sessionUID, "", cl.CommonName, cl.Username, trustedIP, trustedPort, vpnIP, cl.VirtualIPv6, cl.DataCipher,
			connectTime, now, cl.BytesReceived, cl.BytesSent, "active", now, now,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// InsertMgmtSnapshot stores management snapshot.
func (s *SQLiteStore) InsertMgmtSnapshot(ctx context.Context, snapshotTime time.Time, status *mi.Status, stats *mi.LoadStats) error {
	var statsJSON string
	if status != nil {
		if data, err := json.Marshal(status); err == nil {
			statsJSON = string(data)
		}
	}
	var nClients, bytesIn, bytesOut int64
	if stats != nil {
		nClients = stats.NClients
		bytesIn = stats.BytesIn
		bytesOut = stats.BytesOut
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO mgmt_snapshots (snapshot_time, n_clients, bytes_in_total, bytes_out_total, raw_status_json)
            VALUES (?,?,?,?,?)`,
		snapshotTime.Unix(), nClients, bytesIn, bytesOut, statsJSON,
	)
	if err == nil && s.debug {
		s.log.Debug(
			"metrics: saved mgmt snapshot time=%s n_clients=%d bytes_in=%d bytes_out=%d raw_status_len=%d",
			snapshotTime.UTC().Format(time.RFC3339), nClients, bytesIn, bytesOut, len(statsJSON),
		)
	}
	return err
}

// UpdateSessionCryptoFromLog enriches active session crypto fields using log data.
func (s *SQLiteStore) UpdateSessionCryptoFromLog(ctx context.Context, cn, vpnIP, trustedIP string, trustedPort int, tlsVersion, tlsCipher, cipher, hmac string, keyBits int) error {
	sessionUID, _, err := s.findLatestActiveSession(ctx, s.db, cn, vpnIP, trustedIP, trustedPort)
	if err != nil {
		return err
	}
	if sessionUID == "" {
		return nil
	}
	_, err = s.db.ExecContext(
		ctx,
		`UPDATE client_sessions SET
            tls_version=COALESCE(NULLIF(?,''), tls_version),
            tls_cipher=COALESCE(NULLIF(?,''), tls_cipher),
            cipher=COALESCE(NULLIF(?,''), cipher),
            hmac_digest=COALESCE(NULLIF(?,''), hmac_digest),
            key_size_bits=CASE WHEN ?>0 THEN ? ELSE key_size_bits END,
            updated_at=?
        WHERE session_uid=?`,
		tlsVersion, tlsCipher, cipher, hmac, keyBits, keyBits, time.Now().UTC().Unix(), sessionUID,
	)
	return err
}

func (s *SQLiteStore) findLatestActiveSession(ctx context.Context, q querier, commonName, vpnIP, trustedIP string, trustedPort int) (string, int64, error) {
	var row *sql.Row
	switch {
	case vpnIP != "":
		row = q.QueryRowContext(ctx, `SELECT session_uid, connect_time FROM client_sessions WHERE vpn_ip=? AND status='active' ORDER BY connect_time DESC LIMIT 1`, vpnIP)
	case trustedIP != "":
		if trustedPort > 0 {
			row = q.QueryRowContext(ctx, `SELECT session_uid, connect_time FROM client_sessions WHERE trusted_ip=? AND trusted_port=? AND status='active' ORDER BY connect_time DESC LIMIT 1`, trustedIP, trustedPort)
		} else {
			row = q.QueryRowContext(ctx, `SELECT session_uid, connect_time FROM client_sessions WHERE trusted_ip=? AND status='active' ORDER BY connect_time DESC LIMIT 1`, trustedIP)
		}
	default:
		row = q.QueryRowContext(ctx, `SELECT session_uid, connect_time FROM client_sessions WHERE common_name=? AND status='active' ORDER BY connect_time DESC LIMIT 1`, commonName)
	}

	var uid string
	var connect int64
	if err := row.Scan(&uid, &connect); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", 0, nil
		}
		return "", 0, err
	}
	return uid, connect, nil
}

func makeSessionUID(commonName, vpnIP string, connectTime int64) string {
	if connectTime == 0 {
		connectTime = time.Now().UTC().Unix()
	}
	cn := commonName
	if cn == "" {
		cn = "anon"
	}
	ip := vpnIP
	if ip == "" {
		ip = "unknown"
	}
	return fmt.Sprintf("%s-%s-%d", cn, ip, connectTime)
}

func splitHostPort(addr string) (string, int) {
	if addr == "" {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	p, _ := strconv.Atoi(portStr)
	return host, p
}

func parseUnix(v string) int64 {
	if v == "" {
		return time.Now().UTC().Unix()
	}
	v = strings.TrimSpace(v)
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n
	}
	return time.Now().UTC().Unix()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
