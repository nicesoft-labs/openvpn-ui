package lib

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/beego/beego/v2/core/logs"
	mi "github.com/d3vilh/openvpn-server-config/server/mi"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/state"
)

// ObservabilityCollector keeps long running routines that poll OpenVPN
// management interface and persist metrics/events.
type ObservabilityCollector struct {
	client    *mi.Client
	stop      chan struct{}
	wg        sync.WaitGroup
	daemonRef time.Time

	peerInfo   map[string]map[string]string
	peerInfoMu sync.RWMutex
	reconnects uint64
}

// NewObservabilityCollector builds collector using global settings.
func NewObservabilityCollector() *ObservabilityCollector {
	return &ObservabilityCollector{
		client:   mi.NewClient(state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress),
		stop:     make(chan struct{}),
		peerInfo: map[string]map[string]string{},
	}
}

// Start launches pollers and streams.
func (c *ObservabilityCollector) Start() {
	c.wg.Add(4)
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
	go func() {
		defer c.wg.Done()
		c.bytecountLoop()
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
	rawStatus, err := c.client.Execute("status 3")
	if err != nil {
		rawStatus, err = c.client.Execute("status 2")
		if err != nil {
			return err
		}
	}

	status, err := ParseStatusSnapshot(rawStatus)
	if err != nil {
		return err
	}

	rawLoad, errLoad := c.client.Execute("load-stats")
	var loadStats *LoadStatsSnapshot
	if errLoad == nil {
		loadStats, _ = ParseLoadStats(rawLoad)
	}

	version, _ := c.client.GetVersion()
	pid, _ := c.client.GetPid()

	now := time.Now()

	if loadStats != nil && loadStats.Uptime > 0 {
		c.daemonRef = now.Add(-time.Duration(loadStats.Uptime) * time.Second)
	}

	uptimeSeconds := float64(0)
	if loadStats != nil {
		uptimeSeconds = float64(loadStats.Uptime)
	}
	if uptimeSeconds == 0 && !c.daemonRef.IsZero() {
		uptimeSeconds = time.Since(c.daemonRef).Seconds()
	}

	daemon := models.DaemonInfo{Pid: pid, LastSeen: now, DaemonStart: c.daemonRef}
	if version != nil {
		daemon.Version = version.OpenVPN
		daemon.BuildInfo = version.Management
	}
	_ = models.UpsertDaemonInfo(&daemon)

	labels := map[string]string{}
	samples := []models.MetricSample{
		{Name: "openvpn_server_connected_clients", Value: float64(len(status.Clients)), Unit: "sessions", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "status", MetricType: "gauge"},
		{Name: "openvpn_server_tls_established", Value: float64(len(status.Clients)), Unit: "tls", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "status", MetricType: "gauge"},
	}
	if loadStats != nil {
		samples = append(samples,
			models.MetricSample{Name: "openvpn_server_bytes_in_total", Value: float64(loadStats.BytesIn), Unit: "bytes", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "load-stats", MetricType: "counter"},
			models.MetricSample{Name: "openvpn_server_bytes_out_total", Value: float64(loadStats.BytesOut), Unit: "bytes", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "load-stats", MetricType: "counter"},
		)
	}

	if uptimeSeconds > 0 {
		samples = append(samples, models.MetricSample{Name: "openvpn_server_uptime_seconds", Value: uptimeSeconds, Unit: "seconds", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "load-stats", MetricType: "gauge"})
	}

	if qlen, ok := status.GlobalStats["maxbcastmcastqueuelen"]; ok {
		samples = append(samples, models.MetricSample{Name: "openvpn_global_max_bcast_mcast_queue_len", Value: qlen, Unit: "packets", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "status", MetricType: "gauge"})
	}

	routing := make([]models.RoutingCCD, 0)
	routingIndex := make(map[string]RouteStatus)
	for _, route := range status.Routes {
		netAddr, mask := splitRouteWithMask(route.VirtAddr)
		routingIndex[route.VirtAddr] = route
		routing = append(routing, models.RoutingCCD{
			ClientID:   route.ClientID,
			CommonName: route.Common,
			Net:        netAddr,
			Mask:       mask,
			SeenAt:     now,
			Source:     "status",
		})
	}

	for _, cl := range status.Clients {
		lookup := models.MakeClientLookupKey(cl.ClientID, cl.CommonName, cl.RealAddr, cl.VirtAddr)
		route, ok := routingIndex[cl.VirtAddr]
		connectedAt := cl.Connected
		lastRef := time.Time{}
		if ok {
			lastRef = route.LastRef
		}
		peerLabels := c.collectPeerLabels(cl.ClientID, cl.CommonName)
		username := firstNotEmpty(cl.Username, peerLabels["username"])
		realAddr := NormalizeAddr(cl.RealAddr)

		tlsVersion := firstNotEmpty(peerLabels["iv_tls_version"], peerLabels["tls_version"])
		dataCipher := firstNotEmpty(cl.DataCipher, peerLabels["data_channel_cipher"], peerLabels["cipher"], peerLabels["iv_cipher"], peerLabels["iv_ciphers"])
		authAlgo := firstNotEmpty(peerLabels["auth"], peerLabels["iv_auth"], peerLabels["auth_algo"])
		platform := firstNotEmpty(peerLabels["iv_plat"], peerLabels["platform"])
		guiVersion := firstNotEmpty(peerLabels["iv_gui_ver"], peerLabels["gui_version"])
		ovpnVersion := firstNotEmpty(peerLabels["iv_ver"], peerLabels["openvpn_version"])
		proto := firstNotEmpty(peerLabels["iv_proto"], peerLabels["proto"])

		session := models.ClientSession{
			LookupKey:      lookup,
			ClientID:       cl.ClientID,
			PeerID:         cl.PeerID,
			CommonName:     cl.CommonName,
			RealAddr:       realAddr,
			VirtAddr:       cl.VirtAddr,
			VirtAddr6:      cl.VirtAddr6,
			Username:       username,
			ConnectedSince: connectedAt,
			LastRef:        lastRef,
			BytesRxTotal:   cl.BytesRecv,
			BytesTxTotal:   cl.BytesSent,
			TLSVersion:     tlsVersion,
			DataCipher:     dataCipher,
			AuthAlgo:       authAlgo,
			Platform:       platform,
			GUIVersion:     guiVersion,
			OVPNVersion:    ovpnVersion,
			Proto:          proto,
			UpdatedAt:      now,
		}
		_ = models.UpsertClientSession(&session)

		lbl := map[string]string{
			"common_name": cl.CommonName,
			"real_addr":   realAddr,
			"virt_addr":   cl.VirtAddr,
		}
		if cl.VirtAddr6 != "" {
			lbl["virt_addr6"] = cl.VirtAddr6
		}
		if cl.ClientID != "" {
			lbl["client_id"] = cl.ClientID
		}
		if cl.PeerID != "" {
			lbl["peer_id"] = cl.PeerID
		}
		if dataCipher != "" {
			lbl["data_cipher"] = dataCipher
		}
		if authAlgo != "" {
			lbl["auth_algo"] = authAlgo
		}
		if platform != "" {
			lbl["platform"] = platform
		}
		if guiVersion != "" {
			lbl["gui_version"] = guiVersion
		}
		if ovpnVersion != "" {
			lbl["ovpn_version"] = ovpnVersion
		}
		if proto != "" {
			lbl["proto"] = proto
		}
		if tlsVersion != "" {
			lbl["tls_version"] = tlsVersion
		}

		samples = append(samples,
			models.MetricSample{Name: "openvpn_client_bytes_in_total", Value: float64(cl.BytesRecv), Unit: "bytes", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "status", MetricType: "counter"},
			models.MetricSample{Name: "openvpn_client_bytes_out_total", Value: float64(cl.BytesSent), Unit: "bytes", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "status", MetricType: "counter"},
		)
		if !connectedAt.IsZero() {
			samples = append(samples, models.MetricSample{Name: "openvpn_client_session_seconds", Value: time.Since(connectedAt).Seconds(), Unit: "seconds", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "status", MetricType: "gauge"})
		}
		if !lastRef.IsZero() {
			samples = append(samples, models.MetricSample{Name: "openvpn_client_idle_seconds", Value: time.Since(lastRef).Seconds(), Unit: "seconds", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "status", MetricType: "gauge"})
		}
		if dataCipher != "" {
			samples = append(samples, models.MetricSample{Name: "openvpn_client_cipher_info", Value: 1, Unit: "cipher", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "status", MetricType: "gauge"})
		}
		if authAlgo != "" {
			samples = append(samples, models.MetricSample{Name: "openvpn_client_auth_algo_info", Value: 1, Unit: "auth", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "status", MetricType: "gauge"})
		}
		if tlsVersion != "" {
			samples = append(samples, models.MetricSample{Name: "openvpn_client_tls_version_info", Value: 1, Unit: "tls", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "status", MetricType: "gauge"})
		}
	}

	_ = models.SaveMetricSamples(samples)
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

		if err := c.streamCommand("state", "state on", c.handleStateLine); err != nil {
			c.recordReconnect("state", err)
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

		if err := c.streamCommand("log", "log on all", c.handleLogLine); err != nil {
			c.recordReconnect("log", err)
			logs.Warn("log stream: %v", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func (c *ObservabilityCollector) bytecountLoop() {
	for {
		select {
		case <-c.stop:
			return
		default:
		}

		if err := c.streamCommand("bytecount", "bytecount 5", c.handleBytecountLine); err != nil {
			c.recordReconnect("bytecount", err)
			logs.Warn("bytecount stream: %v", err)
			time.Sleep(5 * time.Second)
		}
	}
}

type lineHandler func(string)

func (c *ObservabilityCollector) streamCommand(name, cmd string, handler lineHandler) error {
	conn, err := net.Dial(state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = name

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
	evt, ok := parseStateEvent(line)
	if !ok {
		return
	}

	lbl := map[string]string{"event": evt.Event, "reason": evt.Reason}
	if evt.CommonName != "" {
		lbl["common_name"] = evt.CommonName
	}
	if evt.RealAddr != "" {
		lbl["real_addr"] = evt.RealAddr
	}
	if evt.ClientID != "" {
		lbl["client_id"] = evt.ClientID
	}
	if evt.PeerID != "" {
		lbl["peer_id"] = evt.PeerID
	}
	if evt.VirtAddr != "" {
		lbl["virt_addr"] = evt.VirtAddr
	}

	samples := []models.MetricSample{}
	switch evt.Event {
	case "CONNECTED":
		samples = append(samples,
			models.MetricSample{Name: "openvpn_server_new_sessions_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: evt.Recorded, Source: "state", MetricType: "counter"},
			models.MetricSample{Name: "openvpn_server_tls_handshakes_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: evt.Recorded, Source: "state", MetricType: "counter"},
			models.MetricSample{Name: "openvpn_auth_success_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: evt.Recorded, Source: "state", MetricType: "counter"},
			models.MetricSample{Name: "openvpn_client_connected", Value: 1, Unit: "sessions", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: evt.Recorded, Source: "state", MetricType: "gauge"},
		)
		if evt.ClientID != "" {
			go c.capturePeerInfo(evt.ClientID)
		}
	case "RECONNECTING", "EXITING":
		samples = append(samples,
			models.MetricSample{Name: "openvpn_server_disconnects_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: evt.Recorded, Source: "state", MetricType: "counter"},
			models.MetricSample{Name: "openvpn_client_connected", Value: 0, Unit: "sessions", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: evt.Recorded, Source: "state", MetricType: "gauge"},
		)
	case "TLS_ERROR":
		samples = append(samples, models.MetricSample{Name: "openvpn_server_handshake_errors_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: evt.Recorded, Source: "state", MetricType: "counter"})
	case "AUTH_FAILED":
		samples = append(samples,
			models.MetricSample{Name: "openvpn_server_handshake_errors_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: evt.Recorded, Source: "state", MetricType: "counter"},
			models.MetricSample{Name: "openvpn_auth_fail_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: evt.Recorded, Source: "state", MetricType: "counter"},
		)
	case "INACTIVE":
		samples = append(samples, models.MetricSample{Name: "openvpn_keepalive_timeouts_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: evt.Recorded, Source: "state", MetricType: "counter"})
	}

	_ = models.SaveMetricSamples(samples)
	_ = models.SaveClientEvents([]models.ClientEvent{{Ts: evt.Recorded, ClientID: evt.ClientID, CommonName: evt.CommonName, RealAddr: evt.RealAddr, VirtAddr: evt.VirtAddr, EventType: evt.Event, Reason: evt.Reason, Details: line}})
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
	ts := parseUnixSafe(parts[0])
	level := parts[1]
	message := parts[2]
	recorded := time.Now()
	if !ts.IsZero() {
		recorded = ts
	}

	upperMsg := strings.ToUpper(message)
	lbl := map[string]string{"level": level}
	samples := []models.MetricSample{}

	if strings.Contains(upperMsg, "VERIFY ERROR") {
		lbl["reason"] = "verify_error"
		samples = append(samples, models.MetricSample{Name: "openvpn_tls_verify_fail_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "log", MetricType: "counter"})
	}
	if strings.Contains(upperMsg, "TLS ERROR") {
		lbl["reason"] = "tls_error"
		samples = append(samples, models.MetricSample{Name: "openvpn_server_handshake_errors_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "log", MetricType: "counter"})
	}
	if strings.Contains(upperMsg, "AUTH FAILED") {
		lbl["reason"] = "auth_failed"
		samples = append(samples, models.MetricSample{Name: "openvpn_auth_fail_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "log", MetricType: "counter"})
	}
	if strings.Contains(upperMsg, "AUTH SUCCESS") {
		lbl["reason"] = "auth_success"
		samples = append(samples, models.MetricSample{Name: "openvpn_auth_success_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "log", MetricType: "counter"})
	}
	if strings.Contains(upperMsg, "CRL") && strings.Contains(upperMsg, "REVOKED") {
		lbl["reason"] = "crl_reject"
		samples = append(samples, models.MetricSample{Name: "openvpn_crl_reject_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: recorded, Source: "log", MetricType: "counter"})
	}

	if strings.HasPrefix(message, "CLIENT:ENV") {
		envParts := strings.Split(message, ",")
		info := map[string]string{}
		clientID := ""
		commonName := ""
		for _, part := range envParts[1:] {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.ToLower(kv[0])
			val := kv[1]
			switch key {
			case "clientid", "client_id":
				clientID = val
			case "common_name":
				commonName = val
			default:
				info[key] = val
			}
		}
		c.updatePeerInfo(clientID, commonName, info)
	}

	_ = models.SaveMetricSamples(samples)
	_ = models.SaveClientEvents([]models.ClientEvent{{Ts: recorded, EventType: "LOG", Reason: level, Details: message}})
}

func (c *ObservabilityCollector) handleBytecountLine(line string) {
	if !strings.HasPrefix(line, ">BYTECOUNT_CLI:") {
		return
	}
	sample, ok := ParseBytecountLine(line)
	if !ok {
		return
	}
	lbl := map[string]string{"common_name": sample.CommonName}
	if sample.ClientID != "" {
		lbl["client_id"] = sample.ClientID
	}
	now := time.Now()
	_ = models.SaveMetricSamples([]models.MetricSample{
		{Name: "openvpn_client_bytes_in_total", Value: float64(sample.BytesIn), Unit: "bytes", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "bytecount", MetricType: "counter"},
		{Name: "openvpn_client_bytes_out_total", Value: float64(sample.BytesOut), Unit: "bytes", LabelsJSON: models.MarshalLabels(lbl), RecordedAt: now, Source: "bytecount", MetricType: "counter"},
	})
}

func (c *ObservabilityCollector) recordReconnect(stream string, err error) {
	atomic.AddUint64(&c.reconnects, 1)
	labels := map[string]string{"stream": stream}
	if err != nil {
		labels["reason"] = err.Error()
	}
	_ = models.SaveMetricSamples([]models.MetricSample{{Name: "openvpn_management_reconnects_total", Value: 1, Unit: "events", LabelsJSON: models.MarshalLabels(labels), RecordedAt: time.Now(), Source: "management", MetricType: "counter"}})
}

type stateEvent struct {
	Recorded   time.Time
	Event      string
	Reason     string
	CommonName string
	RealAddr   string
	VirtAddr   string
	ClientID   string
	PeerID     string
}

func parseStateEvent(line string) (stateEvent, bool) {
	if !strings.HasPrefix(line, ">STATE:") {
		return stateEvent{}, false
	}

	payload := strings.TrimPrefix(line, ">STATE:")
	parts := strings.Split(payload, ",")
	if len(parts) < 2 {
		return stateEvent{}, false
	}

	evt := stateEvent{Recorded: time.Now(), Event: parts[1]}
	ts := parseUnixSafe(parts[0])
	if !ts.IsZero() {
		evt.Recorded = ts
	}
	if len(parts) > 2 {
		evt.Reason = parts[2]
	}
	if len(parts) > 3 {
		evt.RealAddr = NormalizeAddr(parts[3])
	}
	if len(parts) > 4 {
		evt.CommonName = parts[4]
	}
	for _, p := range parts[5:] {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.ToLower(kv[0]) {
		case "client-id", "clientid", "client_id":
			evt.ClientID = kv[1]
		case "peer-id", "peer_id":
			evt.PeerID = kv[1]
		case "virtual", "virt_addr":
			evt.VirtAddr = kv[1]
		}
	}

	return evt, true
}

func splitRouteWithMask(route string) (string, string) {
	if strings.Contains(route, "/") {
		parts := strings.SplitN(route, "/", 2)
		return parts[0], parts[1]
	}
	if strings.Contains(route, " ") {
		parts := strings.SplitN(route, " ", 2)
		return parts[0], parts[1]
	}
	if strings.Contains(route, "-") {
		parts := strings.SplitN(route, "-", 2)
		return parts[0], parts[1]
	}
	return route, "255.255.255.255"
}

func firstNotEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (c *ObservabilityCollector) updatePeerInfo(clientID, commonName string, labels map[string]string) {
	key := clientID
	if key == "" {
		key = commonName
	}
	if key == "" {
		return
	}
	c.peerInfoMu.Lock()
	defer c.peerInfoMu.Unlock()
	existing := c.peerInfo[key]
	if existing == nil {
		existing = map[string]string{}
	}
	for k, v := range labels {
		if v == "" {
			continue
		}
		existing[strings.ToLower(k)] = v
	}
	c.peerInfo[key] = existing
}

func (c *ObservabilityCollector) collectPeerLabels(clientID, commonName string) map[string]string {
	c.peerInfoMu.RLock()
	defer c.peerInfoMu.RUnlock()
	if clientID != "" {
		if lbl, ok := c.peerInfo[clientID]; ok {
			return lbl
		}
	}
	if commonName != "" {
		if lbl, ok := c.peerInfo[commonName]; ok {
			return lbl
		}
	}
	return map[string]string{}
}

func (c *ObservabilityCollector) capturePeerInfo(clientID string) {
	if clientID == "" {
		return
	}
	raw, err := c.client.Execute("peer-info " + clientID)
	if err != nil {
		return
	}
	info := ParsePeerInfo(raw)
	c.updatePeerInfo(clientID, "", info)
}
