package mgmtcollector

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	mi "github.com/d3vilh/openvpn-server-config/server/mi"
	"github.com/d3vilh/openvpn-ui/models"
	"golang.org/x/sync/singleflight"
)

const (
	defaultPollInterval = 5 * time.Second
	defaultDialTimeout  = 2 * time.Second
	defaultRWTimeout    = 2 * time.Second

	errorThreshold    = 5
	maxBackoff        = 60 * time.Second
	initialBackoffPow = 1
)

// Config controls polling of the OpenVPN management interface.
type Config struct {
	MINetwork    string
	MIAddress    string
	PollInterval time.Duration
	DialTimeout  time.Duration
	RWTimeout    time.Duration
}

// Snapshot holds cached management data.
type Snapshot struct {
	OvStats     *OvStats  `json:"ovstats,omitempty"`
	OvStatus    *OvStatus `json:"ovstatus,omitempty"`
	Metrics     *Metrics  `json:"metrics"`
	CollectedAt time.Time `json:"collected_at"`
}

type OvStats struct {
	NClients    int64     `json:"NClients"`
	BytesIn     int64     `json:"BytesIn"`
	BytesOut    int64     `json:"BytesOut"`
	Uptime      int64     `json:"Uptime"`
	CollectedAt time.Time `json:"CollectedAt"`
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

type OvStatus struct {
	ClientList  []StatuszClient    `json:"ClientList"`
	GlobalStats map[string]float64 `json:"GlobalStats"`
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
	cfg              Config
	cache            atomic.Value
	once             sync.Once
	group            singleflight.Group
	consecutiveError int
	backoffPower     int
	mu               sync.Mutex
}

var globalCollector = &collector{}

// Start launches the background polling loop.
func Start(cfg Config) {
	globalCollector.once.Do(func() {
		cfg = withDefaults(cfg)
		globalCollector.cfg = cfg
		now := time.Now().UTC()
		globalCollector.storeSnapshot(&Snapshot{Metrics: &Metrics{Ovdaemon: StatuszDaemonState{State: "UNKNOWN"}, Management: StatuszManagement{State: -1, Log: -1, Bytecount: -1}, Global: StatuszGlobal{}, LastSeenTS: now}, CollectedAt: now})
		go globalCollector.loop()
	})
}

// GetSnapshot returns the cached snapshot.
func GetSnapshot() *Snapshot {
	if snap, ok := globalCollector.cache.Load().(*Snapshot); ok && snap != nil {
		return snap
	}
	now := time.Now().UTC()
	return &Snapshot{Metrics: &Metrics{Ovdaemon: StatuszDaemonState{State: "UNKNOWN"}, Management: StatuszManagement{State: -1, Log: -1, Bytecount: -1}, Global: StatuszGlobal{}, LastSeenTS: now}, CollectedAt: now}
}

func (c *collector) loop() {
	c.runPoll()
	for {
		interval := c.nextInterval()
		time.Sleep(interval)
		c.runPoll()
	}
}

func (c *collector) runPoll() {
	_, err, _ := c.group.Do("poll", func() (any, error) {
		return nil, c.collectOnce()
	})
	if err != nil {
		c.registerError()
		return
	}
	c.resetErrors()
}

func (c *collector) collectOnce() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := net.DialTimeout(c.cfg.MINetwork, c.cfg.MIAddress, c.cfg.DialTimeout)
	if err != nil {
		logFailure("dial", err)
		return err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if err := conn.SetReadDeadline(time.Now().Add(c.cfg.RWTimeout)); err != nil {
		logFailure("deadline", err)
		return err
	}

	if _, err := reader.ReadString('\n'); err != nil {
		logFailure("read", err)
		return err
	}

	loadStats, loadErr := c.fetchLoadStats(conn, reader)
	status, statusErr := c.fetchStatus(conn, reader)
	version, versionErr := c.fetchVersion(conn, reader)

	if err := c.closeSession(conn, reader); err != nil {
		logFailure("read", err)
	}

	if loadErr != nil && statusErr != nil {
		return loadErr
	}

	collectedAt := time.Now().UTC()
	snapshot := &Snapshot{CollectedAt: collectedAt}

	if loadStats != nil {
		snapshot.OvStats = &OvStats{
			NClients:    loadStats.NClients,
			BytesIn:     loadStats.BytesIn,
			BytesOut:    loadStats.BytesOut,
			Uptime:      0,
			CollectedAt: collectedAt,
		}
	}

	if status != nil {
		snapshot.OvStatus = convertStatus(status)
	}

	metrics := Metrics{
		Ovdaemon:   StatuszDaemonState{State: "UNKNOWN"},
		Management: StatuszManagement{State: -1, Log: -1, Bytecount: -1},
		Global:     StatuszGlobal{},
		LastSeenTS: collectedAt,
	}

	if snapshot.OvStatus != nil && snapshot.OvStatus.GlobalStats != nil {
		if val, ok := snapshot.OvStatus.GlobalStats["maxbcastmcastqueuelen"]; ok {
			metrics.Global.MaxBcastMcastQueueLen = val
		}
	}

	if statusErr == nil && status != nil {
		metrics.Ovdaemon.State = "CONNECTED"
		metrics.Management = StatuszManagement{State: 1, Log: 1, Bytecount: 1}
	}

	if snapshot.OvStats != nil {
		metrics.LastSeenTS = snapshot.OvStats.CollectedAt
	}

	if versionErr == nil && version != nil {
		metrics.Ovversion = version.OpenVPN
	}

	snapshot.Metrics = &metrics
	c.storeSnapshot(snapshot)
	c.persistUISnapshot(snapshot)

	return nil
}

func (c *collector) fetchLoadStats(conn net.Conn, reader *bufio.Reader) (*mi.LoadStats, error) {
	resp, err := c.runCommand(conn, reader, "load-stats")
	if err != nil {
		logFailure("read", err)
		return nil, err
	}
	ls, err := mi.ParseStats(resp)
	if err != nil {
		logFailure("parse", err)
		return nil, err
	}
	return ls, nil
}

func (c *collector) fetchStatus(conn net.Conn, reader *bufio.Reader) (*mi.Status, error) {
	resp, err := c.runCommand(conn, reader, "status 3")
	if err != nil {
		logFailure("read", err)
		return nil, err
	}
	st, err := mi.ParseStatus(resp)
	if err != nil {
		logFailure("parse", err)
		return nil, err
	}
	return st, nil
}

func (c *collector) fetchVersion(conn net.Conn, reader *bufio.Reader) (*mi.Version, error) {
	resp, err := c.runCommand(conn, reader, "version")
	if err != nil {
		logFailure("read", err)
		return nil, err
	}
	v, err := mi.ParseVersion(resp)
	if err != nil {
		logFailure("parse", err)
		return nil, err
	}
	return v, nil
}

func (c *collector) runCommand(conn net.Conn, reader *bufio.Reader, cmd string) (string, error) {
	if err := conn.SetWriteDeadline(time.Now().Add(c.cfg.RWTimeout)); err != nil {
		logFailure("deadline", err)
		return "", err
	}
	if err := mi.SendCommand(conn, cmd); err != nil {
		logFailure("write", err)
		return "", err
	}
	if err := conn.SetReadDeadline(time.Now().Add(c.cfg.RWTimeout)); err != nil {
		logFailure("deadline", err)
		return "", err
	}
	return mi.ReadResponse(reader)
}

func (c *collector) closeSession(conn net.Conn, reader *bufio.Reader) error {
	if err := conn.SetWriteDeadline(time.Now().Add(c.cfg.RWTimeout)); err != nil {
		logFailure("deadline", err)
		return err
	}
	_ = mi.SendCommand(conn, "quit")
	if err := conn.SetReadDeadline(time.Now().Add(c.cfg.RWTimeout)); err != nil {
		logFailure("deadline", err)
		return err
	}
	_, err := reader.ReadString('\n')
	if err != nil {
		logFailure("read", err)
	}
	return err
}

func (c *collector) storeSnapshot(snapshot *Snapshot) {
	c.cache.Store(snapshot)
}

func (c *collector) resetErrors() {
	c.consecutiveError = 0
	c.backoffPower = initialBackoffPow
}

func (c *collector) registerError() {
	c.consecutiveError++
	if c.consecutiveError >= errorThreshold && c.backoffPower < 8 {
		c.backoffPower++
	}
}

func (c *collector) nextInterval() time.Duration {
	if c.consecutiveError < errorThreshold {
		return c.cfg.PollInterval
	}
	interval := c.cfg.PollInterval * time.Duration(1<<c.backoffPower)
	if interval > maxBackoff {
		return maxBackoff
	}
	return interval
}

func (c *collector) persistUISnapshot(snapshot *Snapshot) {
	payload, err := buildUISnapshotPayload(snapshot)
	if err != nil {
		logs.Warn("build ui snapshot: %v", err)
		return
	}
	if err := models.SaveUISnapshot(payload, snapshot.CollectedAt); err != nil {
		logs.Warn("save ui snapshot: %v", err)
	}
}

func buildUISnapshotPayload(snapshot *Snapshot) (string, error) {
	if snapshot == nil {
		return "", nil
	}

	resp := struct {
		Ovstats  *OvStats  `json:"ovstats,omitempty"`
		Ovstatus *OvStatus `json:"ovstatus,omitempty"`
		Metrics  Metrics   `json:"metrics"`
	}{}

	resp.Ovstats = snapshot.OvStats
	resp.Ovstatus = snapshot.OvStatus

	metrics := Metrics{}
	if snapshot.Metrics != nil {
		metrics = *snapshot.Metrics
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

	resp.Metrics = metrics

	body, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func convertClientBreakdown(status *OvStatus) []ClientBreakdown {
	if status == nil {
		return nil
	}
	breakdown := make([]ClientBreakdown, 0, len(status.ClientList))
	for _, cl := range status.ClientList {
		breakdown = append(breakdown, ClientBreakdown{
			CommonName: cl.CommonName,
			BytesIn:    cl.BytesReceived,
			BytesOut:   cl.BytesSent,
		})
	}
	return breakdown
}

func sumMetricSince(name string, window time.Duration) (int64, error) {
	o := orm.NewOrmUsingDB("metrics")
	since := time.Now().Add(-window)
	samples := []models.MetricSample{}
	if _, err := o.QueryTable(new(models.MetricSample)).Filter("Name", name).Filter("RecordedAt__gte", since).All(&samples, "Value"); err != nil {
		return 0, err
	}
	var total int64
	for i := range samples {
		total += int64(samples[i].Value)
	}
	return total, nil
}

func convertStatus(status *mi.Status) *OvStatus {
	if status == nil {
		return nil
	}
	clients := make([]StatuszClient, 0, len(status.ClientList))
	for _, cl := range status.ClientList {
		clients = append(clients, StatuszClient{
			CommonName:     cl.CommonName,
			RealAddress:    cl.RealAddress,
			VirtualAddress: cl.VirtualAddress,
			BytesReceived:  cl.BytesReceived,
			BytesSent:      cl.BytesSent,
			ConnectedSince: cl.ConnectedSince,
			Username:       cl.Username,
		})
	}
	return &OvStatus{ClientList: clients, GlobalStats: nil}
}

// ComputeETag returns the hash to be used as an ETag header value.
func ComputeETag(snapshot *Snapshot) string {
	if snapshot == nil {
		return ""
	}
	data := []byte(snapshot.CollectedAt.UTC().String())
	sum := sha256.Sum256(data)
	return "\"" + hex.EncodeToString(sum[:]) + "\""
}

func withDefaults(cfg Config) Config {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = defaultDialTimeout
	}
	if cfg.RWTimeout == 0 {
		cfg.RWTimeout = defaultRWTimeout
	}
	return cfg
}

func logFailure(category string, err error) {
	logs.Warn("mgmt collector %s error: %v", category, err)
}
