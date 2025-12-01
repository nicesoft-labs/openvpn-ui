package lib

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego/v2/core/logs"
	mi "github.com/d3vilh/openvpn-server-config/server/mi"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/state"
)

// ObservabilityCollector keeps long running routines that poll OpenVPN
// management interface and persist metrics/events.
type ObservabilityCollector struct {
	client *mi.Client
	stop   chan struct{}
	wg     sync.WaitGroup
}

// NewObservabilityCollector builds collector using global settings.
func NewObservabilityCollector() *ObservabilityCollector {
	return &ObservabilityCollector{
		client: mi.NewClient(state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress),
		stop:   make(chan struct{}),
	}
}

// Start launches pollers and streams.
func (c *ObservabilityCollector) Start() {
	c.wg.Add(3)
	go func() {
		defer c.wg.Done()
		c.pollStatusLoop()
	}()
	go func() {
		defer c.wg.Done()
		c.stateStreamLoop()
	}()
	go func() {
		defer c.wg.Done()
		c.logStreamLoop()
	}()
}

// Stop terminates goroutines.
func (c *ObservabilityCollector) Stop() {
	close(c.stop)
	c.wg.Wait()
}

func (c *ObservabilityCollector) pollStatusLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.collectSnapshot(); err != nil {
				logs.Warn("collect snapshot: %v", err)
			}
		case <-c.stop:
			return
		}
	}
}

func (c *ObservabilityCollector) collectSnapshot() error {
	status, err := c.client.GetStatus()
	if err != nil {
		return err
	}
	loadStats, _ := c.client.GetLoadStats()
	version, _ := c.client.GetVersion()
	pid, _ := c.client.GetPid()

	now := time.Now()
	sysInfo := GetSystemInfo()

	daemon := models.DaemonInfo{Pid: pid, LastSeen: now}
	if version != nil {
		daemon.Version = version.OpenVPN
		daemon.BuildInfo = version.Management
	}
	_ = models.UpsertDaemonInfo(&daemon)

	samples := make([]models.MetricSample, 0)
	labels := map[string]string{}
	samples = append(samples, models.MetricSample{Name: "openvpn_server_connected_clients", Value: float64(len(status.ClientList)), Unit: "sessions", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "status", MetricType: "gauge"})
	if loadStats != nil {
		samples = append(samples,
			models.MetricSample{Name: "openvpn_server_bytes_in_total", Value: float64(loadStats.BytesIn), Unit: "bytes", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "load-stats", MetricType: "counter"},
			models.MetricSample{Name: "openvpn_server_bytes_out_total", Value: float64(loadStats.BytesOut), Unit: "bytes", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "load-stats", MetricType: "counter"},
		)
		samples = append(samples, models.MetricSample{Name: "openvpn_server_tls_established", Value: float64(loadStats.NClients), Unit: "tls", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "load-stats", MetricType: "gauge"})
	}

	samples = append(samples, models.MetricSample{Name: "openvpn_server_uptime_seconds", Value: float64(sysInfo.Uptime), Unit: "seconds", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "os", MetricType: "gauge"})

	clientEvents := make([]models.ClientEvent, 0)
	routing := make([]models.RoutingCCD, 0)

	routingIndex := make(map[string]string)
	for _, route := range status.RoutingTable {
		routingIndex[route.CommonName] = route.LastRefT
		routing = append(routing, models.RoutingCCD{
			ClientID:   "",
			CommonName: route.CommonName,
			Net:        route.VirtualAddress,
			Mask:       "",
			SeenAt:     now,
			Source:     "status",
		})
	}

	for _, cl := range status.ClientList {
		lookup := models.MakeClientLookupKey(cl.ClientID, cl.CommonName, cl.RealAddress, cl.VirtualAddress)
		connectedAt := parseUnix(cl.ConnectedSinceT)
		lastRef := parseUnix(routingIndex[cl.CommonName])
		session := models.ClientSession{
			LookupKey:      lookup,
			ClientID:       cl.ClientID,
			PeerID:         cl.PeerID,
			CommonName:     cl.CommonName,
			RealAddr:       cl.RealAddress,
			VirtAddr:       cl.VirtualAddress,
			VirtAddr6:      cl.VirtualIPv6,
			Username:       cl.Username,
			ConnectedSince: connectedAt,
			LastRef:        lastRef,
			BytesRxTotal:   cl.BytesReceived,
			BytesTxTotal:   cl.BytesSent,
			DataCipher:     cl.DataCipher,
			UpdatedAt:      now,
		}
		_ = models.UpsertClientSession(&session)

		lbl := map[string]string{
			"common_name": cl.CommonName,
			"real_addr":   cl.RealAddress,
			"virt_addr":   cl.VirtualAddress,
			"client_id":   cl.ClientID,
			"peer_id":     cl.PeerID,
		}
		samples = append(samples,
			models.MetricSample{Name: "openvpn_client_bytes_in_total", Value: float64(cl.BytesReceived), Unit: "bytes", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "status", MetricType: "counter"},
			models.MetricSample{Name: "openvpn_client_bytes_out_total", Value: float64(cl.BytesSent), Unit: "bytes", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "status", MetricType: "counter"},
		)
		if !connectedAt.IsZero() {
			samples = append(samples, models.MetricSample{Name: "openvpn_client_session_seconds", Value: time.Since(connectedAt).Seconds(), Unit: "seconds", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "status", MetricType: "gauge"})
		}
		if !lastRef.IsZero() {
			samples = append(samples, models.MetricSample{Name: "openvpn_client_idle_seconds", Value: time.Since(lastRef).Seconds(), Unit: "seconds", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "status", MetricType: "gauge"})
		}
		if cl.DataCipher != "" {
			samples = append(samples, models.MetricSample{Name: "openvpn_client_cipher_info", Value: 1, Unit: "cipher", LabelsJSON: models.MarshalLabels(merge(lbl, map[string]string{"data_cipher": cl.DataCipher})), RecordedAt: now, Source: "status", MetricType: "gauge"})
		}
		if cl.PeerID != "" {
			clientEvents = append(clientEvents, models.ClientEvent{Ts: now, ClientID: cl.ClientID, CommonName: cl.CommonName, RealAddr: cl.RealAddress, VirtAddr: cl.VirtualAddress, EventType: "CONNECTED", Reason: "status", Details: "snapshot"})
		}
	}

	_ = models.SaveMetricSamples(samples)
	_ = models.SaveClientEvents(clientEvents)
	_ = models.SaveRoutingCCD(routing)
	return nil
}

func (c *ObservabilityCollector) stateStreamLoop() {
	for {
		select {
		case <-c.stop:
			return
		default:
		}

		if err := c.streamCommand("state on", c.handleStateLine); err != nil {
			logs.Warn("state stream: %v", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func (c *ObservabilityCollector) logStreamLoop() {
	for {
		select {
		case <-c.stop:
			return
		default:
		}

		if err := c.streamCommand("log on all", c.handleLogLine); err != nil {
			logs.Warn("log stream: %v", err)
			time.Sleep(5 * time.Second)
		}
	}
}

type lineHandler func(string)

func (c *ObservabilityCollector) streamCommand(cmd string, handler lineHandler) error {
	conn, err := net.Dial(state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress)
	if err != nil {
		return err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		return err
	}
	if err := mi.SendCommand(conn, cmd); err != nil {
		return err
	}

	for {
		select {
		case <-c.stop:
			_ = mi.SendCommand(conn, "quit")
			return nil
		default:
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		handler(strings.TrimSpace(line))
	}
}

func (c *ObservabilityCollector) handleStateLine(line string) {
	if !strings.HasPrefix(line, ">STATE:") {
		return
	}
	payload := strings.TrimPrefix(line, ">STATE:")
	parts := strings.Split(payload, ",")
	if len(parts) < 2 {
		return
	}
	ts := parseUnix(parts[0])
	event := parts[1]
	reason := ""
	if len(parts) > 2 {
		reason = parts[2]
	}
	common := ""
	realAddr := ""
	if len(parts) > 3 {
		realAddr = parts[3]
	}
	if len(parts) > 4 {
		common = parts[4]
	}

	now := time.Now()
	recorded := now
	if !ts.IsZero() {
		recorded = ts
	}

	lbl := map[string]string{"event": event, "reason": reason, "common_name": common, "real_addr": realAddr}
	samples := []models.MetricSample{}
	switch event {
	case "CONNECTED":
		samples = append(samples, models.MetricSample{Name: "openvpn_server_new_sessions_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "state", MetricType: "counter"})
		samples = append(samples, models.MetricSample{Name: "openvpn_server_tls_handshakes_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "state", MetricType: "counter"})
	case "RECONNECTING", "EXITING":
		samples = append(samples, models.MetricSample{Name: "openvpn_server_disconnects_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "state", MetricType: "counter"})
	case "TLS_ERROR", "AUTH_FAILED":
		samples = append(samples, models.MetricSample{Name: "openvpn_server_handshake_errors_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "state", MetricType: "counter"})
		if event == "AUTH_FAILED" {
			samples = append(samples, models.MetricSample{Name: "openvpn_auth_fail_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "state", MetricType: "counter"})
		}
	case "INACTIVE":
		samples = append(samples, models.MetricSample{Name: "openvpn_keepalive_timeouts_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "state", MetricType: "counter"})
	}

	_ = models.SaveMetricSamples(samples)
	_ = models.SaveClientEvents([]models.ClientEvent{{Ts: recorded, CommonName: common, RealAddr: realAddr, EventType: event, Reason: reason, Details: line}})
}

func (c *ObservabilityCollector) handleLogLine(line string) {
	if !strings.HasPrefix(line, ">LOG:") {
		return
	}
	payload := strings.TrimPrefix(line, ">LOG:")
	parts := strings.SplitN(payload, ",", 3)
	if len(parts) < 3 {
		return
	}
	ts := parseUnix(parts[0])
	level := parts[1]
	message := parts[2]
	recorded := time.Now()
	if !ts.IsZero() {
		recorded = ts
	}
	lbl := map[string]string{"level": level}
	samples := []models.MetricSample{}
	if strings.Contains(strings.ToUpper(message), "TLS ERROR") {
		lbl["reason"] = "tls_error"
		samples = append(samples, models.MetricSample{Name: "openvpn_tls_verify_fail_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "log", MetricType: "counter"})
	}
	if strings.Contains(strings.ToUpper(message), "AUTH FAILED") {
		lbl["reason"] = "auth_failed"
		samples = append(samples, models.MetricSample{Name: "openvpn_auth_fail_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "log", MetricType: "counter"})
	}
	_ = models.SaveMetricSamples(samples)
	_ = models.SaveClientEvents([]models.ClientEvent{{Ts: recorded, EventType: "LOG", Reason: level, Details: message}})
}

func parseUnix(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if ts, err := strconv.ParseInt(strings.Split(raw, ",")[0], 10, 64); err == nil && ts > 0 {
		return time.Unix(ts, 0)
	}
	return time.Time{}
}

func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
