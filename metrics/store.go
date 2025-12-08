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

// Store abstracts metrics storage backend.
type Store interface {
	InitSchema(ctx context.Context) error

	InsertClientEvent(ctx context.Context, evt *ClientEvent) error

	UpsertSessionOnConnect(ctx context.Context, evt *ClientEvent) error
	UpdateSessionOnDisconnect(ctx context.Context, evt *ClientEvent) error

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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_uid TEXT NOT NULL,
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
	return nil
}

// InsertClientEvent stores raw client event.
func (s *SQLiteStore) InsertClientEvent(ctx context.Context, evt *ClientEvent) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO client_events (
            event_type, event_time, vpn_instance_id, common_name, username, auth_method,
            mfa_used, mfa_ok, trusted_ip, trusted_port, untrusted_ip, untrusted_port,
            vpn_ip, vpn_ipv6, proto, dev, cipher, tls_version, tls_cipher, key_size_bits,
            hmac_digest, compression, dco_enabled, device_os, device_os_ver, device_type,
            device_vendor, device_model, device_id, client_app, client_app_ver, geo_country_code,
            geo_country_name, geo_region, geo_city, geo_asn, geo_org, geo_lat, geo_lon,
            geo_timezone, bytes_received, bytes_sent, packets_received, packets_sent, duration_sec,
            reconnects, disconnect_reason, env_raw, created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		evt.EventType, evt.EventTime.Unix(), evt.VPNInstanceID, evt.CommonName, evt.Username, evt.AuthMethod,
		boolToInt(evt.MFAUsed), boolToInt(evt.MFAOK), evt.TrustedIP, evt.TrustedPort, evt.UntrustedIP, evt.UntrustedPort,
		evt.VPNIP, evt.VPNIPv6, evt.Proto, evt.Dev, evt.Cipher, evt.TLSVersion, evt.TLSCipher, evt.KeySizeBits,
		evt.HMACDigest, evt.Compression, boolToInt(evt.DCOEnabled), evt.DeviceOS, evt.DeviceOSVer, evt.DeviceType,
		evt.DeviceVendor, evt.DeviceModel, evt.DeviceID, evt.ClientApp, evt.ClientAppVer, evt.GeoCountryCode,
		evt.GeoCountryName, evt.GeoRegion, evt.GeoCity, evt.GeoASN, evt.GeoOrg, evt.GeoLat, evt.GeoLon,
		evt.GeoTimezone, evt.BytesReceived, evt.BytesSent, evt.PacketsReceived, evt.PacketsSent, evt.DurationSec,
		evt.Reconnects, evt.DisconnectReason, evt.EnvRaw, evt.CreatedAt.Unix(),
	)
	return err
}

// UpsertSessionOnConnect inserts new session for connect event.
func (s *SQLiteStore) UpsertSessionOnConnect(ctx context.Context, evt *ClientEvent) error {
	uid := fmt.Sprintf("%s-%d", evt.CommonName, evt.EventTime.Unix())
	now := time.Now().UTC().Unix()
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO client_sessions (
            session_uid, vpn_instance_id, common_name, username, department, user_group, user_role,
            trusted_ip, trusted_port, untrusted_ip, untrusted_port, vpn_ip, vpn_ipv6, proto, dev,
            cipher, tls_version, tls_cipher, key_size_bits, hmac_digest, compression, dco_enabled,
            device_os, device_os_ver, device_type, device_vendor, device_model, device_id, client_app, client_app_ver,
            geo_country_code, geo_country_name, geo_region, geo_city, geo_asn, geo_org, geo_lat, geo_lon, geo_timezone,
            auth_method, mfa_used, mfa_ok, is_split_tunnel, is_admin_session, is_external_user,
            connect_time, disconnect_time, duration_sec, last_seen, bytes_in, bytes_out, packets_in, packets_out,
            max_bps_in, max_bps_out, reconnects, status, disconnect_reason, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		uid, evt.VPNInstanceID, evt.CommonName, evt.Username, "", "", "",
		evt.TrustedIP, evt.TrustedPort, evt.UntrustedIP, evt.UntrustedPort, evt.VPNIP, evt.VPNIPv6, evt.Proto, evt.Dev,
		evt.Cipher, evt.TLSVersion, evt.TLSCipher, evt.KeySizeBits, evt.HMACDigest, evt.Compression, boolToInt(evt.DCOEnabled),
		evt.DeviceOS, evt.DeviceOSVer, evt.DeviceType, evt.DeviceVendor, evt.DeviceModel, evt.DeviceID, evt.ClientApp, evt.ClientAppVer,
		evt.GeoCountryCode, evt.GeoCountryName, evt.GeoRegion, evt.GeoCity, evt.GeoASN, evt.GeoOrg, evt.GeoLat, evt.GeoLon, evt.GeoTimezone,
		evt.AuthMethod, boolToInt(evt.MFAUsed), boolToInt(evt.MFAOK), 0, 0, 0,
		evt.EventTime.Unix(), nil, evt.DurationSec, evt.EventTime.Unix(), evt.BytesReceived, evt.BytesSent, evt.PacketsReceived, evt.PacketsSent,
		0, 0, evt.Reconnects, "active", evt.DisconnectReason, now, now,
	)
	return err
}

// UpdateSessionOnDisconnect finalizes active session using disconnect event data.
func (s *SQLiteStore) UpdateSessionOnDisconnect(ctx context.Context, evt *ClientEvent) error {
	sessionID, connectTime, err := s.findLatestActiveSession(ctx, evt.CommonName, evt.VPNIP)
	if err != nil {
		return err
	}
	if sessionID == 0 {
		return errors.New("active session not found")
	}

	duration := evt.DurationSec
	if duration == 0 && connectTime != 0 {
		duration = evt.EventTime.Unix() - connectTime
	}

	_, err = s.db.ExecContext(
		ctx,
		`UPDATE client_sessions SET disconnect_time=?, duration_sec=?, bytes_in=?, bytes_out=?, packets_in=?, packets_out=?,
            reconnects=?, status='disconnected', disconnect_reason=?, updated_at=? WHERE id=?`,
		evt.EventTime.Unix(), duration, evt.BytesReceived, evt.BytesSent, evt.PacketsReceived, evt.PacketsSent,
		evt.Reconnects, evt.DisconnectReason, time.Now().UTC().Unix(), sessionID,
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
		if s.debug {
			s.log.Debug(
				"metrics: status client common_name=%s user=%s vpn_ip=%s real_addr=%s bytes_in=%d bytes_out=%d connected_since=%s",
				cl.CommonName, cl.Username, cl.VirtualAddress, cl.RealAddress, cl.BytesReceived, cl.BytesSent, cl.ConnectedSince,
			)
		}
		trustedIP, trustedPort := splitHostPort(cl.RealAddress)
		vpnIP := cl.VirtualAddress
		connectTime := parseUnix(cl.ConnectedSinceT)

		sessionID, _, err := s.findLatestActiveSession(ctx, cl.CommonName, vpnIP)
		if err != nil {
			return err
		}
		if sessionID == 0 {
			evt := &ClientEvent{
				EventType:     "connect",
				EventTime:     time.Unix(connectTime, 0).UTC(),
				CommonName:    cl.CommonName,
				Username:      cl.Username,
				TrustedIP:     trustedIP,
				TrustedPort:   trustedPort,
				VPNIP:         vpnIP,
				VPNIPv6:       cl.VirtualIPv6,
				Cipher:        cl.DataCipher,
				BytesReceived: cl.BytesReceived,
				BytesSent:     cl.BytesSent,
			}
			if err := s.UpsertSessionOnConnect(ctx, evt); err != nil {
				s.log.Warn("metrics: create session from status: %v", err)
				continue
			}
			sessionID, _, err = s.findLatestActiveSession(ctx, cl.CommonName, vpnIP)
			if err != nil {
				return err
			}
		}

		_, err = s.db.ExecContext(
			ctx,
			`UPDATE client_sessions SET last_seen=?, bytes_in=?, bytes_out=?, cipher=?, trusted_ip=?, trusted_port=?, vpn_ip=?,
                vpn_ipv6=?, status='active', updated_at=? WHERE id=?`,
			now, cl.BytesReceived, cl.BytesSent, cl.DataCipher, trustedIP, trustedPort, vpnIP, cl.VirtualIPv6, now, sessionID,
		)
		if err != nil {
			return err
		}
		if s.debug {
			s.log.Debug("metrics: updated active session id=%d cn=%s vpn_ip=%s bytes_in=%d bytes_out=%d", sessionID, cl.CommonName, vpnIP, cl.BytesReceived, cl.BytesSent)
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

func (s *SQLiteStore) findLatestActiveSession(ctx context.Context, commonName, vpnIP string) (int64, int64, error) {
	var row *sql.Row
	if vpnIP != "" {
		row = s.db.QueryRowContext(ctx, `SELECT id, connect_time FROM client_sessions WHERE vpn_ip=? AND status='active' ORDER BY connect_time DESC LIMIT 1`, vpnIP)
	} else {
		row = s.db.QueryRowContext(ctx, `SELECT id, connect_time FROM client_sessions WHERE common_name=? AND status='active' ORDER BY connect_time DESC LIMIT 1`, commonName)
	}

	var id int64
	var connect int64
	if err := row.Scan(&id, &connect); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	return id, connect, nil
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
