package statuscollector

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/models"
	"golang.org/x/sync/singleflight"
)

const (
	defaultPollInterval       = 2 * time.Second
	defaultSessionHardTimeout = 1 * time.Second
	defaultBackoffMax         = 10 * time.Second
	maxScanBuffer             = 512 * 1024
)

type Config struct {
	StatusFilePath     string
	PollInterval       time.Duration
	SessionHardTimeout time.Duration
	BackoffMax         time.Duration
}

type Snapshot struct {
	OvStats  *OvStats
	OvStatus *OvStatus
	Metrics  *Metrics
	TimeRead time.Time
}

type OvStats struct {
	NClients    int64     `json:"NClients"`
	BytesIn     int64     `json:"BytesIn"`
	BytesOut    int64     `json:"BytesOut"`
	Uptime      int64     `json:"Uptime"`
	CollectedAt time.Time `json:"CollectedAt"`
}

type OvStatus struct {
	ClientList  []StatuszClient    `json:"ClientList"`
	GlobalStats map[string]float64 `json:"GlobalStats"`
}

type StatuszClient struct {
	CommonName     string `json:"CommonName"`
	RealAddress    string `json:"RealAddress"`
	VirtualAddress string `json:"VirtualAddress"`
	BytesReceived  uint64 `json:"BytesReceived"`
	BytesSent      uint64 `json:"BytesSent"`
	ConnectedSince string `json:"ConnectedSince"`
	Username       string `json:"Username"`
}

type Metrics struct {
	Ovdaemon                StatuszDaemonState `json:"ovdaemon"`
	Ovversion               string             `json:"ovversion"`
	Management              StatuszManagement  `json:"management"`
	ManagementReconnects24h int64              `json:"management_reconnects_24h"`
	Global                  StatuszGlobal      `json:"global"`
	Security24h             StatuszSecurity24h `json:"security_24h"`
	ClientBreakdown         []ClientBreakdown  `json:"client_breakdown"`
	LastSeenTS              time.Time          `json:"last_seen_ts"`
}

type StatuszDaemonState struct {
	State string `json:"state"`
}

type StatuszManagement struct {
	State     int `json:"state"`
	Log       int `json:"log"`
	Bytecount int `json:"bytecount"`
}

type StatuszGlobal struct {
	MaxBcastMcastQueueLen float64 `json:"max_bcast_mcast_queue_len"`
}

type StatuszSecurity24h struct {
	AuthFail         int64 `json:"auth_fail"`
	HandshakeErrors  int64 `json:"handshake_errors"`
	TLSVerifyFail    int64 `json:"tls_verify_fail"`
	CRLReject        int64 `json:"crl_reject"`
	KeepaliveTimeout int64 `json:"keepalive_timeouts"`
}

type ClientBreakdown struct {
	CommonName string `json:"common_name"`
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
}

type collector struct {
	cfg      Config
	cache    atomic.Value
	once     sync.Once
	group    singleflight.Group
	mu       sync.Mutex
	backoff  time.Duration
	lastStat fileStat
}

type fileStat struct {
	inode uint64
	size  int64
	mtime time.Time
}

type parsedSnapshot struct {
	title    string
	timeUnix int64
	clients  []clientRow
	routes   []routeRow
	global   map[string]float64
}

type clientRow struct {
	commonName  string
	realAddress string
	virtAddress string
	bytesRx     uint64
	bytesTx     uint64
	connected   int64
	username    string
	clientID    string
	peerID      string
	dataCipher  string
}

type routeRow struct {
	virtAddress string
	commonName  string
	realAddr    string
	lastRef     int64
}

var globalCollector = &collector{}

func Start(cfg Config) {
	globalCollector.once.Do(func() {
		cfg = withDefaults(cfg)
		globalCollector.cfg = cfg
		globalCollector.backoff = cfg.PollInterval
		now := time.Now().UTC()
		globalCollector.storeSnapshot(&Snapshot{Metrics: &Metrics{Ovdaemon: StatuszDaemonState{State: "UNKNOWN"}, Management: StatuszManagement{State: -1, Log: -1, Bytecount: -1}, Global: StatuszGlobal{}, LastSeenTS: now}, TimeRead: now})
		go globalCollector.loop()
	})
}

func GetSnapshot() *Snapshot {
	if snap, ok := globalCollector.cache.Load().(*Snapshot); ok && snap != nil {
		return snap
	}
	now := time.Now().UTC()
	return &Snapshot{Metrics: &Metrics{Ovdaemon: StatuszDaemonState{State: "UNKNOWN"}, Management: StatuszManagement{State: -1, Log: -1, Bytecount: -1}, Global: StatuszGlobal{}, LastSeenTS: now}, TimeRead: now}
}

func (c *collector) loop() {
	c.pollOnce()
	for {
		time.Sleep(c.backoff)
		c.pollOnce()
	}
}

func (c *collector) pollOnce() {
	_, err, _ := c.group.Do("poll", func() (any, error) {
		return nil, c.collect()
	})
	if err != nil {
		logs.Warn("statusfile collector poll error: %v", err)
		c.backoff = backoffInterval(c.backoff, c.cfg.BackoffMax)
		c.writeEmptySnapshot()
		return
	}
	c.backoff = c.cfg.PollInterval
}

func (c *collector) collect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	deadline := time.Now().Add(c.cfg.SessionHardTimeout)
	file, reader, stat, err := c.openAndRead(deadline)
	if err != nil {
		return err
	}
	defer file.Close()

	lines, err := c.readAllLines(reader, deadline)
	if err != nil {
		return err
	}
	if !isCompleteSnapshot(lines) {
		return errors.New("partial snapshot")
	}

	parsed, err := parseStatus(lines)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	snapshot := c.buildSnapshot(parsed, now)
	c.lastStat = stat

	if err := c.persist(parsed, snapshot, now); err != nil {
		logs.Warn("statusfile collector persist: %v", err)
	}

	c.storeSnapshot(snapshot)
	if err := c.persistUISnapshot(snapshot); err != nil {
		logs.Warn("statusfile collector snapshot save: %v", err)
	}

	return nil
}

func (c *collector) openAndRead(deadline time.Time) (*os.File, *bufio.Reader, fileStat, error) {
	f, err := os.OpenFile(c.cfg.StatusFilePath, os.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fileStat{}, err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fileStat{}, err
	}
	stat := extractFileStat(info)

	_ = f.SetDeadline(deadline)
	reader := bufio.NewReader(f)
	return f, reader, stat, nil
}

func (c *collector) readAllLines(reader *bufio.Reader, deadline time.Time) ([]string, error) {
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, maxScanBuffer)

	lines := []string{}
	for scanner.Scan() {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("read timeout")
		}
		line := strings.TrimRight(scanner.Text(), "\r\n")
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return lines, nil
}

func isCompleteSnapshot(lines []string) bool {
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		return strings.TrimSpace(lines[i]) == "END"
	}
	return false
}

func parseStatus(lines []string) (*parsedSnapshot, error) {
	snap := &parsedSnapshot{global: map[string]float64{}}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) == 0 {
			continue
		}
		switch parts[0] {
		case "TITLE":
			snap.title = line
		case "TIME":
			if len(parts) >= 3 {
				if ts, err := strconv.ParseInt(strings.TrimSpace(parts[len(parts)-1]), 10, 64); err == nil {
					snap.timeUnix = ts
				}
			}
		case "CLIENT_LIST":
			cl, err := parseClient(parts)
			if err == nil {
				snap.clients = append(snap.clients, cl)
			}
		case "ROUTING_TABLE":
			rt, err := parseRoute(parts)
			if err == nil {
				snap.routes = append(snap.routes, rt)
			}
		case "GLOBAL_STATS":
			if len(parts) >= 3 {
				if val, err := strconv.ParseFloat(parts[len(parts)-1], 64); err == nil {
					key := strings.ToLower(strings.ReplaceAll(parts[1], " ", "_"))
					key = strings.ReplaceAll(key, "/", "_")
					snap.global[key] = val
				}
			}
		}
	}
	return snap, nil
}

func parseClient(parts []string) (clientRow, error) {
	if len(parts) < 13 {
		return clientRow{}, fmt.Errorf("invalid CLIENT_LIST")
	}
	rx, err := strconv.ParseUint(parts[5], 10, 64)
	if err != nil {
		return clientRow{}, err
	}
	tx, err := strconv.ParseUint(parts[6], 10, 64)
	if err != nil {
		return clientRow{}, err
	}
	connected, err := strconv.ParseInt(parts[8], 10, 64)
	if err != nil {
		return clientRow{}, err
	}
	return clientRow{
		commonName:  parts[1],
		realAddress: parts[2],
		virtAddress: parts[3],
		bytesRx:     rx,
		bytesTx:     tx,
		connected:   connected,
		username:    parts[9],
		clientID:    parts[10],
		peerID:      parts[11],
		dataCipher:  parts[12],
	}, nil
}

func parseRoute(parts []string) (routeRow, error) {
	if len(parts) < 6 {
		return routeRow{}, fmt.Errorf("invalid ROUTING_TABLE")
	}
	lastRef, err := strconv.ParseInt(parts[5], 10, 64)
	if err != nil {
		return routeRow{}, err
	}
	return routeRow{
		virtAddress: parts[1],
		commonName:  parts[2],
		realAddr:    parts[3],
		lastRef:     lastRef,
	}, nil
}

func (c *collector) buildSnapshot(parsed *parsedSnapshot, now time.Time) *Snapshot {
	if parsed == nil {
		return nil
	}
	status := &OvStatus{ClientList: make([]StatuszClient, 0, len(parsed.clients)), GlobalStats: map[string]float64{}}
	totalIn := int64(0)
	totalOut := int64(0)

	for _, cl := range parsed.clients {
		status.ClientList = append(status.ClientList, StatuszClient{
			CommonName:     cl.commonName,
			RealAddress:    cl.realAddress,
			VirtualAddress: cl.virtAddress,
			BytesReceived:  cl.bytesRx,
			BytesSent:      cl.bytesTx,
			ConnectedSince: time.Unix(cl.connected, 0).UTC().Format(time.RFC3339),
			Username:       cl.username,
		})
		totalIn += int64(cl.bytesRx)
		totalOut += int64(cl.bytesTx)
	}

	for k, v := range parsed.global {
		status.GlobalStats[k] = v
	}

	stats := &OvStats{
		NClients:    int64(len(parsed.clients)),
		BytesIn:     totalIn,
		BytesOut:    totalOut,
		Uptime:      0,
		CollectedAt: now,
	}

	metrics := &Metrics{Ovdaemon: StatuszDaemonState{State: "CONNECTED"}, Management: StatuszManagement{State: 1, Log: 0, Bytecount: 0}, Global: StatuszGlobal{}}
	if val, ok := status.GlobalStats["maxbcastmcastqueuelen"]; ok {
		metrics.Global.MaxBcastMcastQueueLen = val
	}
	metrics.ClientBreakdown = convertClientBreakdown(status)
	metrics.LastSeenTS = now
	metrics.Ovversion = extractVersion(parsed.title)

	return &Snapshot{OvStats: stats, OvStatus: status, Metrics: metrics, TimeRead: now}
}

func (c *collector) persist(parsed *parsedSnapshot, snapshot *Snapshot, now time.Time) error {
	if parsed == nil || snapshot == nil {
		return nil
	}

	samples := buildMetricSamples(parsed, now)
	if err := models.SaveMetricSamples(samples); err != nil {
		return err
	}

	sessions := make([]*models.ClientSession, 0, len(parsed.clients))
	routes := make([]models.RoutingCCD, 0, len(parsed.routes))
	routeIndex := map[string]routeRow{}
	for _, rt := range parsed.routes {
		routeIndex[rt.virtAddress] = rt
		routes = append(routes, models.RoutingCCD{Net: rt.virtAddress, CommonName: rt.commonName, RealAddr: rt.realAddr, SeenAt: now, Source: "statusfile"})
	}

	ovVersion := extractVersion(parsed.title)

	for _, cl := range parsed.clients {
		lookup := models.MakeClientLookupKey(cl.clientID, cl.commonName, cl.realAddress, cl.virtAddress)
		rt := routeIndex[cl.virtAddress]
		session := &models.ClientSession{
			LookupKey:      lookup,
			ClientID:       cl.clientID,
			PeerID:         cl.peerID,
			CommonName:     cl.commonName,
			RealAddr:       cl.realAddress,
			VirtAddr:       cl.virtAddress,
			Username:       cl.username,
			ConnectedSince: time.Unix(cl.connected, 0).UTC(),
			LastRef:        time.Unix(rt.lastRef, 0).UTC(),
			BytesRxTotal:   cl.bytesRx,
			BytesTxTotal:   cl.bytesTx,
			DataCipher:     cl.dataCipher,
			OVPNVersion:    ovVersion,
			UpdatedAt:      now,
		}
		sessions = append(sessions, session)
	}

	for _, s := range sessions {
		_ = models.UpsertClientSession(s)
	}
	if len(routes) > 0 {
		_ = models.SaveRoutingCCD(routes)
	}

	daemon := models.DaemonInfo{Version: ovVersion, LastSeen: now}
	_ = models.UpsertDaemonInfo(&daemon)

	return nil
}

func buildMetricSamples(parsed *parsedSnapshot, now time.Time) []models.MetricSample {
	totalIn := float64(0)
	totalOut := float64(0)
	for _, cl := range parsed.clients {
		totalIn += float64(cl.bytesRx)
		totalOut += float64(cl.bytesTx)
	}

	samples := []models.MetricSample{
		{Name: "openvpn_server_connected_clients", Value: float64(len(parsed.clients)), Unit: "sessions", RecordedAt: now, Source: "statusfile", MetricType: "gauge"},
		{Name: "openvpn_server_bytes_in_total", Value: totalIn, Unit: "bytes", RecordedAt: now, Source: "statusfile", MetricType: "counter"},
		{Name: "openvpn_server_bytes_out_total", Value: totalOut, Unit: "bytes", RecordedAt: now, Source: "statusfile", MetricType: "counter"},
	}

	version := extractVersion(parsed.title)
	if version != "" {
		samples = append(samples, models.MetricSample{Name: "openvpn_version_info", Value: 1, LabelsJSON: models.MarshalLabels(map[string]string{"version": version}), RecordedAt: now, Source: "statusfile", MetricType: "gauge"})
	}

	if qlen, ok := parsed.global["max_bcast_mcast_queue_length"]; ok {
		samples = append(samples, models.MetricSample{Name: "openvpn_global_max_bcast_mcast_queue_len", Value: qlen, Unit: "packets", RecordedAt: now, Source: "statusfile", MetricType: "gauge"})
	}
	if qlen, ok := parsed.global["maxbcastmcastqueuelen"]; ok {
		samples = append(samples, models.MetricSample{Name: "openvpn_global_max_bcast_mcast_queue_len", Value: qlen, Unit: "packets", RecordedAt: now, Source: "statusfile", MetricType: "gauge"})
	}

	for _, cl := range parsed.clients {
		labels := map[string]string{"common_name": cl.commonName, "real_addr": cl.realAddress, "virt_addr": cl.virtAddress}
		samples = append(samples,
			models.MetricSample{Name: "openvpn_client_cli_bytes_in", Value: float64(cl.bytesRx), Unit: "bytes", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "statusfile", MetricType: "counter"},
			models.MetricSample{Name: "openvpn_client_cli_bytes_out", Value: float64(cl.bytesTx), Unit: "bytes", LabelsJSON: models.MarshalLabels(labels), RecordedAt: now, Source: "statusfile", MetricType: "counter"},
		)
	}

	return samples
}

func convertClientBreakdown(status *OvStatus) []ClientBreakdown {
	if status == nil {
		return nil
	}
	breakdown := make([]ClientBreakdown, 0, len(status.ClientList))
	for _, cl := range status.ClientList {
		breakdown = append(breakdown, ClientBreakdown{CommonName: cl.CommonName, BytesIn: cl.BytesReceived, BytesOut: cl.BytesSent})
	}
	return breakdown
}

func (c *collector) persistUISnapshot(snapshot *Snapshot) error {
	if snapshot == nil {
		return nil
	}

	metrics := snapshot.Metrics
	if metrics == nil {
		metrics = &Metrics{}
	}

	metrics.ClientBreakdown = convertClientBreakdown(snapshot.OvStatus)

	if sec, err := sumMetricSince("openvpn_auth_fail_total", 24*time.Hour); err == nil {
		metrics.Security24h.AuthFail = sec
	}
	if sec, err := sumMetricSince("openvpn_server_handshake_errors_total", 24*time.Hour); err == nil {
		metrics.Security24h.HandshakeErrors = sec
	}
	if sec, err := sumMetricSince("openvpn_tls_verify_fail_total", 24*time.Hour); err == nil {
		metrics.Security24h.TLSVerifyFail = sec
	}
	if sec, err := sumMetricSince("openvpn_crl_reject_total", 24*time.Hour); err == nil {
		metrics.Security24h.CRLReject = sec
	}
	if sec, err := sumMetricSince("openvpn_keepalive_timeouts_total", 24*time.Hour); err == nil {
		metrics.Security24h.KeepaliveTimeout = sec
	}
	if reconnects, err := sumMetricSince("openvpn_management_reconnects_total", 24*time.Hour); err == nil {
		metrics.ManagementReconnects24h = reconnects
	}

	payload, err := buildUISnapshotPayload(snapshot, metrics)
	if err != nil {
		return err
	}
	return models.SaveUISnapshot(payload, snapshot.TimeRead)
}

func sumMetricSince(name string, window time.Duration) (int64, error) {
	o := models.GetMetricsOrm()
	since := time.Now().Add(-window)
	samples := []models.MetricSample{}
	if _, err := o.QueryTable(new(models.MetricSample)).Filter("Name", name).Filter("RecordedAt__gte", since).Filter("Source", "statusfile").All(&samples, "Value"); err != nil {
		return 0, err
	}
	var total int64
	for i := range samples {
		total += int64(samples[i].Value)
	}
	return total, nil
}

func buildUISnapshotPayload(snapshot *Snapshot, metrics *Metrics) (string, error) {
	if snapshot == nil {
		return "", nil
	}
	resp := struct {
		Ovstats  *OvStats  `json:"ovstats,omitempty"`
		Ovstatus *OvStatus `json:"ovstatus,omitempty"`
		Metrics  *Metrics  `json:"metrics"`
	}{Ovstats: snapshot.OvStats, Ovstatus: snapshot.OvStatus, Metrics: metrics}

	body, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *collector) writeEmptySnapshot() {
	now := time.Now().UTC()
	empty := &Snapshot{OvStats: &OvStats{CollectedAt: now}, OvStatus: &OvStatus{ClientList: []StatuszClient{}, GlobalStats: map[string]float64{}}, Metrics: &Metrics{Ovdaemon: StatuszDaemonState{State: "UNKNOWN"}, Management: StatuszManagement{State: -1, Log: -1, Bytecount: -1}, Global: StatuszGlobal{}, LastSeenTS: now}, TimeRead: now}
	c.storeSnapshot(empty)
	_ = c.persistUISnapshot(empty)
}

func backoffInterval(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}

func (c *collector) storeSnapshot(snapshot *Snapshot) {
	c.cache.Store(snapshot)
}

func extractFileStat(info os.FileInfo) fileStat {
	st := fileStat{size: info.Size(), mtime: info.ModTime()}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		st.inode = uint64(sys.Ino)
	}
	return st
}

func extractVersion(title string) string {
	parts := strings.Fields(title)
	for i := 0; i < len(parts); i++ {
		if strings.EqualFold(parts[i], "OpenVPN") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func withDefaults(cfg Config) Config {
	if cfg.StatusFilePath == "" {
		cfg.StatusFilePath = filepath.Clean("/var/log/status.log")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.SessionHardTimeout == 0 {
		cfg.SessionHardTimeout = defaultSessionHardTimeout
	}
	if cfg.BackoffMax == 0 {
		cfg.BackoffMax = defaultBackoffMax
	}
	return cfg
}
