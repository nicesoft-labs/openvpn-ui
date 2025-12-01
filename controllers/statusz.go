package controllers

import (
	"errors"
	"time"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	mi "github.com/d3vilh/openvpn-server-config/server/mi"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/state"
)

type StatuszResponse struct {
	Ovstats  *StatuszLoadStats `json:"ovstats,omitempty"`
	Ovstatus *StatuszStatus    `json:"ovstatus,omitempty"`
	Metrics  StatuszMetrics    `json:"metrics"`
}

type StatuszLoadStats struct {
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

type StatuszStatus struct {
	ClientList  []StatuszClient    `json:"ClientList"`
	GlobalStats map[string]float64 `json:"GlobalStats"`
}

type StatuszMetrics struct {
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

type StatuszController struct {
	BaseController
}

func (c *StatuszController) NestPrepare() {
	if !c.IsLogin {
		c.CustomAbort(401, "unauthorized")
	}
}

// Statusz returns combined snapshot for UI polling.
func (c *StatuszController) Statusz() {
	payload, err := BuildStatuszSnapshot()
	if err != nil {
		logs.Warn("statusz snapshot: %v", err)
	}
	c.Data["json"] = payload
	_ = c.ServeJSON()
}

// Metrics exposes metrics section from the snapshot.
func (c *StatuszController) Metrics() {
	payload, err := BuildStatuszSnapshot()
	if err != nil {
		logs.Warn("metrics snapshot: %v", err)
	}
	c.Data["json"] = payload.Metrics
	_ = c.ServeJSON()
}

// BuildStatuszSnapshot constructs UI payload using live management data and stored metrics.
func BuildStatuszSnapshot() (*StatuszResponse, error) {
	client := mi.NewClient(state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress)
	resp := &StatuszResponse{}

	status, statusErr := client.GetStatus()
	if statusErr == nil && status != nil {
		resp.Ovstatus = convertStatus(status)
	}

	loadStats, loadErr := client.GetLoadStats()
	if loadErr == nil && loadStats != nil {
		resp.Ovstats = &StatuszLoadStats{
			NClients:    loadStats.NClients,
			BytesIn:     loadStats.BytesIn,
			BytesOut:    loadStats.BytesOut,
			Uptime:      0,
			CollectedAt: time.Now().UTC(),
		}
	}

	version, _ := client.GetVersion()

	metrics := StatuszMetrics{
		Ovdaemon:   StatuszDaemonState{State: "UNKNOWN"},
		Management: StatuszManagement{State: -1, Log: -1, Bytecount: -1},
		Global:     StatuszGlobal{},
		LastSeenTS: time.Now().UTC(),
	}

	if resp.Ovstatus != nil && resp.Ovstatus.GlobalStats != nil {
		if val, ok := resp.Ovstatus.GlobalStats["maxbcastmcastqueuelen"]; ok {
			metrics.Global.MaxBcastMcastQueueLen = val
		}
	}

	if statusErr == nil {
		metrics.Ovdaemon.State = "CONNECTED"
		metrics.Management = StatuszManagement{State: 1, Log: 1, Bytecount: 1}
	}

	if resp.Ovstats != nil {
		metrics.LastSeenTS = resp.Ovstats.CollectedAt
	}

	if version != nil {
		metrics.Ovversion = version.OpenVPN
	}

	metrics.ClientBreakdown = convertClientBreakdown(resp.Ovstatus)

	sec24h, err := loadSecurity24h()
	if err != nil {
		logs.Warn("load security 24h: %v", err)
	}
	metrics.Security24h = sec24h

	reconnects, err := sumMetricSince("openvpn_management_reconnects_total", 24*time.Hour)
	if err != nil {
		logs.Warn("load management reconnects: %v", err)
	} else {
		metrics.ManagementReconnects24h = reconnects
	}

	resp.Metrics = metrics

	if statusErr != nil && loadErr != nil {
		return resp, errors.New("management unavailable")
	}

	return resp, nil
}

func convertStatus(status *mi.Status) *StatuszStatus {
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
	return &StatuszStatus{ClientList: clients, GlobalStats: nil}
}

func convertClientBreakdown(status *StatuszStatus) []ClientBreakdown {
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

func loadSecurity24h() (StatuszSecurity24h, error) {
	authFail, err := sumMetricSince("openvpn_auth_fail_total", 24*time.Hour)
	if err != nil {
		return StatuszSecurity24h{}, err
	}
	handshake, err := sumMetricSince("openvpn_server_handshake_errors_total", 24*time.Hour)
	if err != nil {
		return StatuszSecurity24h{}, err
	}
	tlsFail, err := sumMetricSince("openvpn_tls_verify_fail_total", 24*time.Hour)
	if err != nil {
		return StatuszSecurity24h{}, err
	}
	crlReject, err := sumMetricSince("openvpn_crl_reject_total", 24*time.Hour)
	if err != nil {
		return StatuszSecurity24h{}, err
	}
	keepalive, err := sumMetricSince("openvpn_keepalive_timeouts_total", 24*time.Hour)
	if err != nil {
		return StatuszSecurity24h{}, err
	}

	return StatuszSecurity24h{
		AuthFail:         authFail,
		HandshakeErrors:  handshake,
		TLSVerifyFail:    tlsFail,
		CRLReject:        crlReject,
		KeepaliveTimeout: keepalive,
	}, nil
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
