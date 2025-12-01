package controllers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/models"
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

// Get рендерит главную страницу. Данные берём ТОЛЬКО из БД (UISnapshot),
// никаких обращений к management из HTTP-слоя.
func (c *MainController) Get() {
	// Системная информация (локально, не mgmt)
	sysInfo := lib.GetSystemInfo()
	c.Data["sysinfo"] = sysInfo

	// Готовый JSON-снимок для UI из БД
	payload, _, err := models.GetUISnapshot()
	if err != nil || payload == "" {
		logs.Warn(fmt.Sprintf("status snapshot empty: %v", err))
		// Отдаём пустые структуры — шаблон корректно отрисует плейсхолдеры.
		c.Data["ovstatus"] = nil
		c.Data["ovstats"] = nil
		c.Data["metrics"] = nil
		c.Data["ovversion"] = ""
		c.TplName = "index.html"
		return
	}

	// Парсим только нужные поля
	var snap struct {
		Ovstatus any `json:"ovstatus"`
		Ovstats  any `json:"ovstats"`
		Metrics  struct {
			Ovversion string `json:"ovversion"`
			// Остальные поля остаются внутри metrics как map для шаблона
			// чтобы не терять динамику, прочитаем всё как generic:
			Raw json.RawMessage `json:"-"`
		} `json:"metrics"`
	}

	// Второй проход: чтобы передать metrics целиком в шаблон
	var generic map[string]any
	if err := json.Unmarshal([]byte(payload), &generic); err != nil {
		logs.Warn(fmt.Sprintf("status snapshot unmarshal(top): %v", err))
	}

	if err := json.Unmarshal([]byte(payload), &snap); err != nil {
		logs.Warn(fmt.Sprintf("status snapshot unmarshal(fields): %v", err))
	}

	// Достаём metrics как map, чтобы шаблон мог читать произвольные поля
	var metrics any
	if m, ok := generic["metrics"]; ok {
		metrics = m
	}

	c.Data["ovstatus"] = snap.Ovstatus
	c.Data["ovstats"] = snap.Ovstats
	c.Data["metrics"] = metrics
	c.Data["ovversion"] = snap.Metrics.Ovversion

	c.TplName = "index.html"
}

// ВНИМАНИЕ: UI больше не использует типы из management-пакета.
// Если нужны агрегаты для дашборда — формируйте их из содержимого JSON-снимка
// (ovstats/ovstatus/metrics), уже извлечённого из БД. Ниже оставлен каркас
// (при необходимости можно распаковать ovstatus/ovstats в конкретные структуры).
func buildDashboardMetrics(
	_ovstatus any, // ожидается объект со списком клиентов
	_ovstats any,  // ожидается объект со сводной статистикой
	sysInfo lib.SystemInfo,
	managementAvailable bool,
) dashboardMetrics {
	dm := dashboardMetrics{}

	// При необходимости распарсить _ovstatus в структуру с ClientList и заполнить clientMetrics.
	clientMetrics := make([]clientMetric, 0)

	now := time.Now().Unix()
	_ = now // заготовка, если добавите расчёт длительностей из ovstatus

	dm.ClientBreakdown = clientMetrics

	totalClients := float64(len(clientMetrics))
	totalBytesIn := 0.0
	totalBytesOut := 0.0

	// Если нужно — распакуйте _ovstats и возьмите:
	//  - NClients -> totalClients
	//  - BytesIn/BytesOut -> totalBytesIn/totalBytesOut

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
