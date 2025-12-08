package metrics

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
)

// Handler handles HTTP events from OpenVPN hooks.
type Handler struct {
	cfg   MetricsConfig
	store Store
	log   *logs.BeeLogger
	debug bool
}

// NewHandler creates new metrics HTTP handler.
func NewHandler(cfg MetricsConfig, store Store, log *logs.BeeLogger) *Handler {
	return &Handler{cfg: cfg, store: store, log: log, debug: web.BConfig.RunMode == web.DEV}
}

// HandleClientEvent consumes client-connect/disconnect events.
func (h *Handler) HandleClientEvent(w http.ResponseWriter, r *http.Request) {
	if h.debug {
		h.log.Debug(
			"metrics: client-event request method=%s remote=%s content_length=%d",
			r.Method, r.RemoteAddr, r.ContentLength,
		)
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		if h.debug {
			h.log.Debug("metrics: rejected client-event with invalid method=%s", r.Method)
		}
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		http.Error(w, "forbidden", http.StatusForbidden)
		if h.debug {
			h.log.Debug("metrics: forbidden client-event remote=%s host_parse_err=%v", r.RemoteAddr, err)
		}
		return
	}

	// Парсим форму (если уже распарсена где-то раньше, проблем не будет).
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		if h.debug {
			h.log.Debug("metrics: client-event parse form error: %v", err)
		}
		return
	}

	// Для debug-режима логируем "сырой" payload в виде x-www-form-urlencoded.
	// Это фактически то же самое тело запроса, только нормализованное.
	if h.debug {
		h.log.Debug("metrics: client-event form=%s", r.Form.Encode())
	}

	evt := h.parseEventFromRequest(r)
	if h.debug {
		h.log.Debug(
			"metrics: parsed client-event type=%s user=%s cn=%s vpn_ip=%s trusted_ip=%s bytes_in=%d bytes_out=%d duration=%ds",
			evt.EventType, evt.Username, evt.CommonName, evt.VPNIP, evt.TrustedIP, evt.BytesReceived, evt.BytesSent, evt.DurationSec,
		)
		if evt.EnvRaw != "" {
			h.log.Debug("metrics: client-event env_raw=%s", evt.EnvRaw)
		}
	}

	ctx := r.Context()
	if sqlite, ok := h.store.(*SQLiteStore); ok {
		tx, err := sqlite.db.BeginTx(ctx, nil)
		if err != nil {
			h.log.Warn("metrics: begin tx: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := sqlite.InsertClientEventTx(ctx, tx, evt); err != nil {
			tx.Rollback()
			h.log.Warn("metrics: InsertClientEventTx: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		switch evt.EventType {
		case "connect":
			if err := sqlite.UpsertSessionOnConnectTx(ctx, tx, evt); err != nil {
				tx.Rollback()
				h.log.Warn("metrics: UpsertSessionOnConnectTx: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		case "disconnect":
			if err := sqlite.UpdateSessionOnDisconnectTx(ctx, tx, evt); err != nil {
				tx.Rollback()
				h.log.Warn("metrics: UpdateSessionOnDisconnectTx: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			h.log.Warn("metrics: commit tx: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	} else {
		if err := h.store.InsertClientEvent(ctx, evt); err != nil {
			h.log.Warn("metrics: InsertClientEvent: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			if h.debug {
				h.log.Debug("metrics: failed to persist client-event to store: %v", err)
			}
			return
		}

		switch evt.EventType {
		case "connect":
			if err := h.store.UpsertSessionOnConnect(ctx, evt); err != nil {
				h.log.Warn("metrics: UpsertSessionOnConnect: %v", err)
				if h.debug {
					h.log.Debug("metrics: connect session upsert error: %v", err)
				}
			}
		case "disconnect":
			if err := h.store.UpdateSessionOnDisconnect(ctx, evt); err != nil {
				h.log.Warn("metrics: UpdateSessionOnDisconnect: %v", err)
				if h.debug {
					h.log.Debug("metrics: disconnect session update error: %v", err)
				}
			}
		}
	}

	if h.debug {
		h.log.Debug("metrics: client-event processed successfully type=%s", evt.EventType)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) parseEventFromRequest(r *http.Request) *ClientEvent {
	now := time.Now().UTC()
	evtTime := now
	if tsStr := r.FormValue("event_time"); tsStr != "" {
		if ts, err := strconv.ParseInt(tsStr, 10, 64); err == nil {
			evtTime = time.Unix(ts, 0).UTC()
		}
	}

	parseInt := func(name string) int {
		if v := r.FormValue(name); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
			h.log.Warn("metrics: invalid int field %s=%s", name, v)
		}
		return 0
	}

	parseUint := func(name string) uint64 {
		if v := r.FormValue(name); v != "" {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				return n
			}
			h.log.Warn("metrics: invalid uint field %s=%s", name, v)
		}
		return 0
	}

	parseBool := func(name string) bool {
		if v := r.FormValue(name); v != "" {
			if b, err := strconv.ParseBool(v); err == nil {
				return b
			}
			if v == "1" {
				return true
			}
			h.log.Warn("metrics: invalid bool field %s=%s", name, v)
		}
		return false
	}

	evt := &ClientEvent{
		EventType:      r.FormValue("event_type"),
		EventTime:      evtTime,
		VPNInstanceID:  r.FormValue("vpn_instance_id"),
		CommonName:     r.FormValue("common_name"),
		Username:       r.FormValue("username"),
		AuthMethod:     r.FormValue("auth_method"),
		MFAUsed:        parseBool("mfa_used"),
		MFAOK:          parseBool("mfa_ok"),
		TrustedIP:      r.FormValue("trusted_ip"),
		TrustedPort:    parseInt("trusted_port"),
		UntrustedIP:    r.FormValue("untrusted_ip"),
		UntrustedPort:  parseInt("untrusted_port"),
		VPNIP:          r.FormValue("vpn_ip"),
		VPNIPv6:        r.FormValue("vpn_ipv6"),
		Proto:          r.FormValue("proto"),
		Dev:            r.FormValue("dev"),
		Cipher:         r.FormValue("cipher"),
		TLSVersion:     r.FormValue("tls_version"),
		TLSCipher:      r.FormValue("tls_cipher"),
		KeySizeBits:    parseInt("key_size_bits"),
		HMACDigest:     r.FormValue("hmac_digest"),
		Compression:    r.FormValue("compression"),
		DCOEnabled:     parseBool("dco_enabled"),
		DeviceOS:       r.FormValue("device_os"),
		DeviceOSVer:    r.FormValue("device_os_ver"),
		DeviceType:     r.FormValue("device_type"),
		DeviceVendor:   r.FormValue("device_vendor"),
		DeviceModel:    r.FormValue("device_model"),
		DeviceID:       r.FormValue("device_id"),
		ClientApp:      r.FormValue("client_app"),
		ClientAppVer:   r.FormValue("client_app_ver"),
		GeoCountryCode: r.FormValue("geo_country_code"),
		GeoCountryName: r.FormValue("geo_country_name"),
		GeoRegion:      r.FormValue("geo_region"),
		GeoCity:        r.FormValue("geo_city"),
		GeoASN:         r.FormValue("geo_asn"),
		GeoOrg:         r.FormValue("geo_org"),
		GeoLat:         parseFloat(r.FormValue("geo_lat")),
		GeoLon:         parseFloat(r.FormValue("geo_lon")),
		GeoTimezone:    r.FormValue("geo_timezone"),

		BytesReceived:   parseUint("bytes_received"),
		BytesSent:       parseUint("bytes_sent"),
		PacketsReceived: parseUint("packets_received"),
		PacketsSent:     parseUint("packets_sent"),
		DurationSec:     int64(parseInt("duration_sec")),
		Reconnects:      int64(parseInt("reconnects")),

		DisconnectReason: r.FormValue("disconnect_reason"),
		EnvRaw:           r.FormValue("env_raw"),
		CreatedAt:        now,
	}

	if evt.EventType == "" {
		evt.EventType = "unknown"
	}

	return evt
}

func parseFloat(v string) float64 {
	if v == "" {
		return 0
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0
	}
	return f
}

// NewForbiddenLocalOnlyError returns standard error for forbidden access.
func NewForbiddenLocalOnlyError() error {
	return fmt.Errorf("metrics endpoint is restricted to local connections")
}
