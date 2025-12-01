package controllers

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/services/mgmtcollector"
)

type StatuszResponse struct {
	Ovstats  *mgmtcollector.OvStats  `json:"ovstats,omitempty"`
	Ovstatus *mgmtcollector.OvStatus `json:"ovstatus,omitempty"`
	Metrics  mgmtcollector.Metrics   `json:"metrics"`
}

type (
	StatuszSecurity24h = mgmtcollector.StatuszSecurity24h
	ClientBreakdown    = mgmtcollector.ClientBreakdown
)

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
	payload := BuildStatuszSnapshot()
	if err := setETagHeader(c, payload); err != nil {
		logs.Warn("statusz etag: %v", err)
	}
	c.Ctx.Output.Header("Cache-Control", "no-store, must-revalidate")
	c.Data["json"] = payload
	_ = c.ServeJSON()
}

// Metrics exposes metrics section from the snapshot.
func (c *StatuszController) Metrics() {
	payload := BuildStatuszSnapshot()
	if err := setETagHeader(c, payload); err != nil {
		logs.Warn("metrics etag: %v", err)
	}
	c.Ctx.Output.Header("Cache-Control", "no-store, must-revalidate")
	c.Data["json"] = payload.Metrics
	_ = c.ServeJSON()
}

// BuildStatuszSnapshot constructs UI payload using cached management data and stored metrics.
func BuildStatuszSnapshot() *StatuszResponse {
	snap := mgmtcollector.GetSnapshot()
	resp := &StatuszResponse{
		Ovstats:  snap.OvStats,
		Ovstatus: snap.OvStatus,
	}

	metrics := mgmtcollector.Metrics{}
	if snap.Metrics != nil {
		metrics = *snap.Metrics
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

	return resp
}

func setETagHeader(c *StatuszController, payload *StatuszResponse) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(body)
	c.Ctx.Output.Header("ETag", fmt.Sprintf("\"%x\"", hash))
	return nil
}

func convertClientBreakdown(status *mgmtcollector.OvStatus) []ClientBreakdown {
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
