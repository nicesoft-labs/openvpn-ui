package controllers

import (
	"fmt"
	"strconv"
	"time"

	"github.com/beego/beego/v2/core/logs"
	mi "github.com/d3vilh/openvpn-server-config/server/mi"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/state"
)

type dashboardMetric struct {
	Name        string  `json:"name"`
	Value       float64 `json:"value"`
	Unit        string  `json:"unit"`
	Description string  `json:"description"`
}

type clientMetric struct {
	CommonName string  `json:"common_name"`
	RealAddr   string  `json:"real_addr"`
	VirtAddr   string  `json:"virt_addr"`
	BytesIn    uint64  `json:"bytes_in"`
	BytesOut   uint64  `json:"bytes_out"`
	SessionSec float64 `json:"session_sec"`
	IdleSec    float64 `json:"idle_sec"`
	Info       string  `json:"info"`
}

type dashboardMetrics struct {
	ServerMetrics   []dashboardMetric `json:"server_metrics"`
	CryptoMetrics   []dashboardMetric `json:"crypto_metrics"`
	RoutingMetrics  []dashboardMetric `json:"routing_metrics"`
	AuthMetrics     []dashboardMetric `json:"auth_metrics"`
	HealthMetrics   []dashboardMetric `json:"health_metrics"`
	QualityMetrics  []dashboardMetric `json:"quality_metrics"`
	ClientBreakdown []clientMetric    `json:"client_breakdown"`
}

type MainController struct {
	BaseController
}

func (c *MainController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}
	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: "Status",
	}
}

func (c *MainController) Get() {
	sysInfo := lib.GetSystemInfo()
	c.Data["sysinfo"] = sysInfo
	lib.Dump(lib.GetSystemInfo())
	managementAvailable := true
	client := mi.NewClient(state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress)
	status, err := client.GetStatus()
	if err != nil {
		logs.Error(err)
		logs.Warn(fmt.Sprintf("passed client line: %s", client))
		logs.Warn(fmt.Sprintf("error: %s", err))
		managementAvailable = false
	} else {
		c.Data["ovstatus"] = status
	}
	lib.Dump(status)

	version, err := client.GetVersion()
	if err != nil {
		logs.Error(err)
		managementAvailable = false
	} else {
		c.Data["ovversion"] = version.OpenVPN
	}
	lib.Dump(version)

	pid, err := client.GetPid()
	if err != nil {
		logs.Error(err)
		managementAvailable = false
	} else {
		c.Data["ovpid"] = pid
	}
	lib.Dump(pid)

	loadStats, err := client.GetLoadStats()
	if err != nil {
		logs.Error(err)
		managementAvailable = false
	} else {
		c.Data["ovstats"] = loadStats
	}
	lib.Dump(loadStats)

	metrics := buildDashboardMetrics(status, loadStats, sysInfo, managementAvailable)
	c.Data["metrics"] = metrics

	if managementAvailable {
		if err := models.SaveMetrics(buildMetricRecords(metrics)); err != nil {
			logs.Error(err)
		}
	}

	c.TplName = "index.html"
}

func buildDashboardMetrics(status *mi.Status, loadStats *mi.LoadStats, sysInfo lib.SystemInfo, managementAvailable bool) dashboardMetrics {
	dm := dashboardMetrics{}

	clientMetrics := make([]clientMetric, 0)
	routingIndex := make(map[string]*mi.RoutingPath)
	if status != nil {
		for _, route := range status.RoutingTable {
			routingIndex[route.CommonName] = route
		}
	}

	now := time.Now().Unix()

	if status != nil {
		for _, cl := range status.ClientList {
			sessionDuration := parseUnixDiff(now, cl.ConnectedSinceT)
			idle := 0.0
			if route, ok := routingIndex[cl.CommonName]; ok {
				idle = parseUnixDiff(now, route.LastRefT)
			}

			clientMetrics = append(clientMetrics, clientMetric{
				CommonName: cl.CommonName,
				RealAddr:   cl.RealAddress,
				VirtAddr:   cl.VirtualAddress,
				BytesIn:    cl.BytesReceived,
				BytesOut:   cl.BytesSent,
				SessionSec: sessionDuration,
				IdleSec:    idle,
				Info:       "TLS established",
			})
		}
	}

	dm.ClientBreakdown = clientMetrics

	totalClients := float64(len(clientMetrics))
	totalBytesIn := 0.0
	totalBytesOut := 0.0
	if loadStats != nil && managementAvailable {
		totalClients = float64(loadStats.NClients)
		totalBytesIn = float64(loadStats.BytesIn)
		totalBytesOut = float64(loadStats.BytesOut)
	}

	uptimeSeconds := float64(sysInfo.Uptime)
	probeSuccess := 1.0
	if !managementAvailable {
		uptimeSeconds = 0
		probeSuccess = 0
	}

	dm.ServerMetrics = []dashboardMetric{
		{
			Name:        "openvpn_server_connected_clients",
			Value:       totalClients,
			Unit:        "сеансов",
			Description: "Текущее число клиентов online",
		},
		{
			Name:        "openvpn_server_bytes_in_total",
			Value:       totalBytesIn,
			Unit:        "байт",
			Description: "Всего получено",
		},
		{
			Name:        "openvpn_server_bytes_out_total",
			Value:       totalBytesOut,
			Unit:        "байт",
			Description: "Всего отправлено",
		},
		{
			Name:        "openvpn_server_uptime_seconds",
			Value:       uptimeSeconds,
			Unit:        "сек",
			Description: "Аптайм демона по данным системы",
		},
		{
			Name:        "openvpn_server_tls_established",
			Value:       totalClients,
			Unit:        "TLS",
			Description: "Активные TLS-сессии",
		},
	}

	dm.CryptoMetrics = []dashboardMetric{
		{
			Name:        "openvpn_client_cipher_info",
			Value:       totalClients,
			Unit:        "TLS",
			Description: "Распределение шифров (placeholder)",
		},
		{
			Name:        "openvpn_client_auth_algo_info",
			Value:       totalClients,
			Unit:        "Auth",
			Description: "Распределение auth дайджестов (placeholder)",
		},
		{
			Name:        "openvpn_client_tls_version_info",
			Value:       totalClients,
			Unit:        "версии",
			Description: "Версии TLS клиентов (placeholder)",
		},
	}

	dm.RoutingMetrics = []dashboardMetric{
		{
			Name:        "openvpn_push_mode_info",
			Value:       totalClients,
			Unit:        "клиентов",
			Description: "Full-tunnel vs split-tunnel",
		},
		{
			Name:        "openvpn_client_pushed_routes",
			Value:       float64(len(clientMetrics)),
			Unit:        "маршрутов",
			Description: "Количество маршрутов на клиента (placeholder)",
		},
		{
			Name:        "openvpn_ccd_iroutes_total",
			Value:       0,
			Unit:        "iroute",
			Description: "Статистика iroute (нет данных)",
		},
	}

	dm.AuthMetrics = []dashboardMetric{
		{Name: "openvpn_auth_success_total", Value: totalClients, Unit: "успех", Description: "Успешные логины (placeholder)"},
		{Name: "openvpn_auth_fail_total", Value: 0, Unit: "ошибки", Description: "Неуспешные попытки"},
		{Name: "openvpn_crl_reject_total", Value: 0, Unit: "CRL", Description: "Отклонения по CRL"},
	}

	dm.HealthMetrics = []dashboardMetric{
		{Name: "openvpn_tun_rx_bytes_total", Value: totalBytesIn, Unit: "байт", Description: "TUN RX"},
		{Name: "openvpn_tun_tx_bytes_total", Value: totalBytesOut, Unit: "байт", Description: "TUN TX"},
		{Name: "probe_success", Value: probeSuccess, Unit: "ok", Description: "Порт 1194 слушается"},
	}

	dm.QualityMetrics = []dashboardMetric{
		{Name: "openvpn_keepalive_timeouts_total", Value: 0, Unit: "таймаутов", Description: "PING/PING-RESTART (placeholder)"},
		{Name: "openvpn_server_new_sessions_total", Value: totalClients, Unit: "сессий", Description: "Новые сессии/сек"},
		{Name: "openvpn_server_disconnects_total", Value: 0, Unit: "разрывы", Description: "Дропы и ошибки рукопожатия"},
	}

	return dm
}

func buildMetricRecords(dm dashboardMetrics) []models.MetricRecord {
	records := make([]models.MetricRecord, 0, len(dm.ServerMetrics)+len(dm.CryptoMetrics)+len(dm.RoutingMetrics)+len(dm.AuthMetrics)+len(dm.HealthMetrics)+len(dm.QualityMetrics))

	appendRecords := func(category string, metrics []dashboardMetric) {
		for _, m := range metrics {
			records = append(records, models.MetricRecord{
				Category:    category,
				Name:        m.Name,
				Value:       m.Value,
				Unit:        m.Unit,
				Description: m.Description,
			})
		}
	}

	appendRecords("server", dm.ServerMetrics)
	appendRecords("crypto", dm.CryptoMetrics)
	appendRecords("routing", dm.RoutingMetrics)
	appendRecords("auth", dm.AuthMetrics)
	appendRecords("health", dm.HealthMetrics)
	appendRecords("quality", dm.QualityMetrics)

	return records
}

func parseUnixDiff(now int64, raw string) float64 {
	ts, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0
	}
	if ts == 0 {
		return 0
	}
	return float64(now - ts)
}
