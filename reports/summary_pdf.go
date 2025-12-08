package reports

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"time"
	"unicode"

	"github.com/d3vilh/openvpn-ui/metrics"
	"github.com/jung-kurt/gofpdf"
)

const (
	baseFont      = "DejaVuSans"
	primaryColorR = 34
	primaryColorG = 64
	primaryColorB = 120

	bottomMargin   = 20.0
	tableRowHeight = 8.0
)

// GenerateSummaryPDF builds enterprise-styled VPN summary report.
func GenerateSummaryPDF(ctx context.Context, store metrics.Store, from, to time.Time, w io.Writer) error {
	kpi, err := metrics.AggregateSessionsKPI(ctx, store, from, to)
	if err != nil {
		return err
	}

	sessionsByDay, err := metrics.AggregateSessionsByDay(ctx, store, from, to)
	if err != nil {
		return err
	}

	topUsersByTraffic, err := metrics.AggregateTopUsersByTraffic(ctx, store, from, to, 10)
	if err != nil {
		return err
	}

	topUsersByDuration, err := metrics.AggregateTopUsersByDuration(ctx, store, from, to, 10)
	if err != nil {
		return err
	}

	topClientsByTraffic, err := metrics.AggregateTopClientsByTraffic(ctx, store, from, to, 10)
	if err != nil {
		return err
	}

	mfaStats, err := metrics.AggregateMFAStats(ctx, store, from, to)
	if err != nil {
		return err
	}

	authMethods, err := metrics.AggregateAuthMethodStats(ctx, store, from, to)
	if err != nil {
		return err
	}

	osDistribution, err := metrics.AggregateOsDistribution(ctx, store, from, to)
	if err != nil {
		return err
	}

	deviceTypes, err := metrics.AggregateDeviceTypeStats(ctx, store, from, to)
	if err != nil {
		return err
	}

	clientApps, err := metrics.AggregateClientAppStats(ctx, store, from, to, 10)
	if err != nil {
		return err
	}

	cipherDistribution, err := metrics.AggregateCipherDistribution(ctx, store, from, to)
	if err != nil {
		return err
	}

	countryDistribution, err := metrics.AggregateCountryDistribution(ctx, store, from, to)
	if err != nil {
		return err
	}

	problemClients, err := metrics.AggregateProblemClients(ctx, store, from, to, 10)
	if err != nil {
		return err
	}

	buckets, err := metrics.AggregateSessionDurationBuckets(ctx, store, from, to)
	if err != nil {
		return err
	}

	heatmap, err := metrics.AggregateUsageHeatmap(ctx, store, from, to)
	if err != nil {
		return err
	}

	eventsTimeline, err := metrics.AggregateEventsTimeline(ctx, store, from, to, 30)
	if err != nil {
		return err
	}

	pdf := newReport()
	if err := registerFonts(pdf); err != nil {
		return err
	}

	pdf.AliasNbPages("")
	pdf.SetFooterFunc(func() {
		pdf.SetY(-18)
		pdf.SetDrawColor(210, 210, 210)
		pdf.Line(10, pdf.GetY(), 200, pdf.GetY())
		pdf.SetTextColor(120, 120, 120)

		pdf.SetFont(baseFont, "", 8)
		pdf.CellFormat(0, 5, "© NiceVPN - продукт компании  ООО \"НАЙС СОФТ ГРУПП\". Работает на НАЙС.ОС - Российское ПО запись в реестре №30128 от 22.10.2025", "", 1, "L", false, 0, "")

		pdf.SetFont(baseFont, "", 9)
		pdf.CellFormat(0, 8, fmt.Sprintf("Страница %d / {nb}", pdf.PageNo()), "", 0, "R", false, 0, "")
		pdf.SetY(pdf.GetY() - 2)
		pdf.SetX(10)
		pdf.CellFormat(0, 8, "NiceVPN / NiceSOFT", "", 0, "L", false, 0, "")
	})

	// Страницы в логичном порядке для руководителя
	addTitlePage(pdf, from, to)
	addKPISummary(pdf, kpi)
	addExecutiveSummary(pdf, kpi, sessionsByDay, topUsersByTraffic, topClientsByTraffic)
	addSessionsByDay(pdf, sessionsByDay)
	addPeakDaysByTraffic(pdf, sessionsByDay)
	addTopUsers(pdf, kpi, topUsersByTraffic, topUsersByDuration)
	addTopUsersByDuration(pdf, topUsersByDuration)
	addTopClients(pdf, kpi, topClientsByTraffic)
	addSecuritySection(pdf, mfaStats, authMethods)
	addDeviceProfileSection(pdf, mfaStats.TotalSessions, osDistribution, deviceTypes, clientApps)
	addCryptoAndCountrySection(pdf, cipherDistribution, countryDistribution)
	addProblemClientsSection(pdf, problemClients)
	addDurationAndUsagePatternsSection(pdf, mfaStats.TotalSessions, buckets, heatmap, eventsTimeline)

	if pdf.Err() {
		return pdf.Error()
	}

	return pdf.Output(w)
}

func newReport() *gofpdf.Fpdf {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 18, 15)
	pdf.SetAutoPageBreak(true, 20)
	return pdf
}

func registerFonts(pdf *gofpdf.Fpdf) error {
	regular := filepath.Join("assets", "fonts", "DejaVuSans.ttf")
	bold := filepath.Join("assets", "fonts", "DejaVuSans-Bold.ttf")

	pdf.AddUTF8Font(baseFont, "", regular)
	if pdf.Err() {
		return fmt.Errorf("failed to add font %s: %w", regular, pdf.Error())
	}

	pdf.AddUTF8Font(baseFont, "B", bold)
	if pdf.Err() {
		return fmt.Errorf("failed to add font %s: %w", bold, pdf.Error())
	}

	return nil
}

func addTitlePage(pdf *gofpdf.Fpdf, from, to time.Time) {
	pdf.AddPage()
	addTopBand(pdf)

	pdf.SetFont(baseFont, "", 12)
	pdf.SetTextColor(90, 90, 90)
	pdf.Cell(0, 8, "Отчёт по использованию VPN-инфраструктуры")
	pdf.Ln(10)

	pdf.SetFont(baseFont, "B", 22)
	pdf.SetTextColor(primaryColorR, primaryColorG, primaryColorB)
	pdf.Cell(0, 14, "NiceVPN — Сводный отчёт по VPN")
	pdf.Ln(18)

	pdf.SetFont(baseFont, "", 14)
	pdf.SetTextColor(30, 30, 30)
	pdf.Cell(0, 10, fmt.Sprintf("Период: %s — %s", formatDate(from), formatDate(to)))
	pdf.Ln(8)

	now := time.Now()
	pdf.SetFont(baseFont, "", 11)
	pdf.SetTextColor(80, 80, 80)
	pdf.Cell(0, 8, fmt.Sprintf("Время генерации (UTC): %s", now.UTC().Format(time.RFC3339)))
	pdf.Ln(6)
	pdf.Cell(0, 8, fmt.Sprintf("Время генерации (local): %s", now.Local().Format(time.RFC3339)))
	pdf.Ln(14)

	pdf.SetFont(baseFont, "", 11)
	pdf.MultiCell(0, 7, "Отчёт предназначен для руководителей и отражает ключевые показатели использования VPN. Показана динамика по дням, концентрация трафика по пользователям и клиентам, а также пиковые нагрузки за выбранный период.", "", "L", false)

	pdf.SetY(254)
	pdf.SetTextColor(100, 100, 100)
	pdf.SetFont(baseFont, "", 10)
	pdf.Cell(0, 6, "Отчёт сформирован системой NiceVPN")
	pdf.Ln(6)
	pdf.Cell(0, 6, "© NiceVPN - продукт компании  ООО \"НАЙС СОФТ ГРУПП\". Работает на НАЙС.ОС - Российское ПО запись в реестре №30128 от 22.10.2025")
}

func addTopBand(pdf *gofpdf.Fpdf) {
	pdf.SetFillColor(primaryColorR, primaryColorG, primaryColorB)
	pdf.Rect(0, 0, 210, 25, "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont(baseFont, "B", 14)
	pdf.SetXY(15, 8)
	pdf.Cell(0, 8, "NiceSOFT / NiceVPN")
	pdf.Ln(18)
	pdf.SetXY(15, 20)
	pdf.SetDrawColor(255, 255, 255)
	pdf.SetLineWidth(0.4)
	pdf.Line(15, 22, 195, 22)
	pdf.SetY(32)
	pdf.SetTextColor(30, 30, 30)
}

func addSectionHeader(pdf *gofpdf.Fpdf, title string, subtitle string) {
	pdf.SetFont(baseFont, "B", 16)
	pdf.SetTextColor(primaryColorR, primaryColorG, primaryColorB)
	pdf.Cell(0, 10, title)
	pdf.Ln(9)
	if subtitle != "" {
		pdf.SetFont(baseFont, "", 11)
		pdf.SetTextColor(90, 90, 90)
		pdf.Cell(0, 7, subtitle)
		pdf.Ln(6)
	}
	pdf.SetTextColor(30, 30, 30)
	pdf.SetFont(baseFont, "", 11)
	pdf.Ln(2)
}

func ensureTableRowSpace(pdf *gofpdf.Fpdf, rowHeight float64, header func()) {
	_, y := pdf.GetXY()
	_, pageH := pdf.GetPageSize()
	if y+rowHeight+bottomMargin > pageH {
		pdf.AddPage()
		if header != nil {
			addTopBand(pdf)
			header()
		}
	}
}

func addKPISummary(pdf *gofpdf.Fpdf, kpi metrics.MetricsKPI) {
	pdf.AddPage()
	addTopBand(pdf)
	addSectionHeader(pdf, "Ключевые показатели за период", "Основные метрики использования NiceVPN")

	totalBytes := kpi.TotalBytesIn + kpi.TotalBytesOut

	cards := []struct {
		title string
		value string
	}{
		{"Всего сессий", fmt.Sprintf("%d", kpi.TotalSessions)},
		{"Уникальные пользователи", fmt.Sprintf("%d", kpi.UniqueUsers)},
		{"Суммарный трафик", fmt.Sprintf("%s GiB", formatGiB(totalBytes))},
		{"Средняя длительность сессии", fmt.Sprintf("%s мин", formatMinutes(kpi.AvgSessionDurationSec))},
		{"Максимум одновременных клиентов", fmt.Sprintf("%d", kpi.MaxConcurrentSessions)},
	}

	cols := 2
	cardW := 90.0
	cardH := 28.0
	gapX := 10.0
	gapY := 6.0
	startX := pdf.GetX()
	startY := pdf.GetY()

	for i, card := range cards {
		row := i / cols
		col := i % cols
		if col == 0 {
			ensureTableRowSpace(pdf, cardH+gapY, nil)
		}
		x := startX + float64(col)*(cardW+gapX)
		y := startY + float64(row)*(cardH+gapY)
		drawKPICard(pdf, x, y, cardW, cardH, card.title, card.value)
	}

	rows := (len(cards) + cols - 1) / cols
	pdf.SetY(startY + float64(rows)*(cardH+gapY) + 7)
}

func drawKPICard(pdf *gofpdf.Fpdf, x, y, w, h float64, title, value string) {
	pdf.SetFillColor(247, 250, 253)
	pdf.SetDrawColor(225, 232, 240)
	pdf.RoundedRect(x, y, w, h, 2, "FD", "1234")

	pdf.SetXY(x+5, y+5)
	pdf.SetFont(baseFont, "", 10)
	pdf.SetTextColor(110, 110, 110)
	pdf.CellFormat(w-10, 6, title, "", 0, "L", false, 0, "")

	pdf.SetXY(x+5, y+12)
	pdf.SetFont(baseFont, "B", 18)
	pdf.SetTextColor(primaryColorR, primaryColorG, primaryColorB)
	pdf.CellFormat(w-10, 10, value, "", 0, "L", false, 0, "")
}

// Краткая текстовая аналитика для руководителя
func addExecutiveSummary(pdf *gofpdf.Fpdf, kpi metrics.MetricsKPI, stats []metrics.AnalyticsDayStat, users []metrics.AnalyticsUserTraffic, clients []metrics.TopClientPoint) {
	pdf.AddPage()
	addTopBand(pdf)
	addSectionHeader(pdf, "Краткая аналитическая сводка", "Интерпретация ключевых показателей за период")

	totalBytes := kpi.TotalBytesIn + kpi.TotalBytesOut

	var daysWithSessions uint64
	var maxDaySessions int64
	var maxDaySessionsDate string
	var maxDayTrafficBytes uint64
	var maxDayTrafficDate string

	for _, d := range stats {
		daysWithSessions++
		if int64(d.Sessions) > maxDaySessions {
			maxDaySessions = int64(d.Sessions)
			maxDaySessionsDate = d.Date
		}
		dayBytes := d.BytesIn + d.BytesOut
		if dayBytes > maxDayTrafficBytes {
			maxDayTrafficBytes = dayBytes
			maxDayTrafficDate = d.Date
		}
	}

	avgSessionsPerDay := float64(0)
	avgTrafficGiBPerDay := float64(0)
	if daysWithSessions > 0 {
		avgSessionsPerDay = float64(kpi.TotalSessions) / float64(daysWithSessions)
		avgTrafficGiBPerDay = bytesToGiB(totalBytes) / float64(daysWithSessions)
	}

	// Концентрация трафика по пользователям
	var topUserLabel string
	var topUserShare, top3UsersShare float64
	if totalBytes > 0 && len(users) > 0 {
		var top3Bytes uint64
		for i, u := range users {
			userBytes := u.BytesIn + u.BytesOut
			if i == 0 {
				topUserLabel = formatUserLabel(u.Username, u.CommonName)
				topUserShare = float64(userBytes) / float64(totalBytes)
			}
			if i < 3 {
				top3Bytes += userBytes
			}
		}
		top3UsersShare = float64(top3Bytes) / float64(totalBytes)
	}

	// Концентрация трафика по клиентам
	var topClientLabel string
	var topClientShare float64
	if totalBytes > 0 && len(clients) > 0 {
		c := clients[0]
		topClientLabel = c.CommonName
		topClientShare = float64(c.TotalBytes) / float64(totalBytes)
	}

	pdf.SetFont(baseFont, "", 11)
	pdf.SetTextColor(40, 40, 40)

	bullet := func(text string) {
		pdf.CellFormat(5, 6, "•", "", 0, "L", false, 0, "")
		pdf.MultiCell(0, 6, text, "", "L", false)
	}

	bullet(fmt.Sprintf("Всего сессий за период: %d. В среднем %.1f сессий в день (максимум %d в день %s).",
		kpi.TotalSessions, avgSessionsPerDay, maxDaySessions, safeDateLabel(maxDaySessionsDate)))

	bullet(fmt.Sprintf("Суммарный трафик: %s GiB. В среднем %.2f GiB в день (максимальная нагрузка %s: %s GiB).",
		formatGiB(totalBytes), avgTrafficGiBPerDay, safeDateLabel(maxDayTrafficDate), formatGiB(maxDayTrafficBytes)))

	if kpi.MaxConcurrentSessions > 0 {
		bullet(fmt.Sprintf("Пиковое одновременное количество подключённых клиентов: %d.", kpi.MaxConcurrentSessions))
	}

	if topUserLabel != "" {
		bullet(fmt.Sprintf("Топ-1 пользователь по трафику: %s (%.1f%% всего трафика). Доля топ-3 пользователей: %.1f%%.",
			topUserLabel, topUserShare*100, top3UsersShare*100))
	}

	if topClientLabel != "" {
		bullet(fmt.Sprintf("Топ-1 клиент (сервер/узел) по трафику: %s (%.1f%% общего трафика).",
			topClientLabel, topClientShare*100))
	}

	pdf.Ln(4)
	pdf.SetFont(baseFont, "", 10)
	pdf.SetTextColor(100, 100, 100)
	pdf.MultiCell(0, 5, "Данные основаны на агрегированной статистике сессий и снимках состояния OpenVPN. Для детальной технической аналитики используйте web-интерфейс NiceVPN.", "", "L", false)
}

func addSessionsByDay(pdf *gofpdf.Fpdf, stats []metrics.AnalyticsDayStat) {
	if len(stats) == 0 {
		return
	}

	headers := []string{"Дата", "Сессии", "Трафик входящий (GiB)", "Трафик исходящий (GiB)", "Сред. длительность (мин)"}
	widths := []float64{30, 25, 45, 45, 35}

	headerRow := func() {
		addSectionHeader(pdf, "Сводка по дням", "Динамика сессий и трафика")
		renderTableHeader(pdf, headers, widths)
	}

	pdf.AddPage()
	addTopBand(pdf)
	headerRow()

	for idx, d := range stats {
		ensureTableRowSpace(pdf, tableRowHeight, headerRow)
		fill := idx%2 == 0
		drawTableRow(pdf, widths, []string{
			d.Date,
			fmt.Sprintf("%d", d.Sessions),
			formatGiB(d.BytesIn),
			formatGiB(d.BytesOut),
			formatMinutes(d.AvgDurationSec),
		}, fill, false, nil)
	}
}

// Топ-5 дней по объёму трафика
func addPeakDaysByTraffic(pdf *gofpdf.Fpdf, stats []metrics.AnalyticsDayStat) {
	if len(stats) == 0 {
		return
	}

	type dayAgg struct {
		Date           string
		Sessions       int64
		TotalBytes     uint64
		AvgDurationSec float64
	}

	days := make([]dayAgg, len(stats))
	for i, d := range stats {
		days[i] = dayAgg{
			Date:           d.Date,
			Sessions:       int64(d.Sessions),
			TotalBytes:     d.BytesIn + d.BytesOut,
			AvgDurationSec: d.AvgDurationSec,
		}
	}

	sort.Slice(days, func(i, j int) bool { return days[i].TotalBytes > days[j].TotalBytes })
	if len(days) > 5 {
		days = days[:5]
	}

	headers := []string{"#", "Дата", "Сессий", "Трафик (GiB)", "Сред. длит. (мин)"}
	widths := []float64{10, 40, 30, 50, 50}

	headerRow := func() {
		addSectionHeader(pdf, "Дни с максимальной нагрузкой", "Топ-5 дней по объёму переданных данных")
		renderTableHeader(pdf, headers, widths)
	}

	pdf.AddPage()
	addTopBand(pdf)
	headerRow()

	for idx, d := range days {
		ensureTableRowSpace(pdf, tableRowHeight, headerRow)
		fill := idx%2 == 0
		drawTableRow(pdf, widths, []string{
			fmt.Sprintf("%d", idx+1),
			d.Date,
			fmt.Sprintf("%d", d.Sessions),
			formatGiB(d.TotalBytes),
			formatMinutes(d.AvgDurationSec),
		}, fill, idx == 0, nil)
	}
}

// Топ пользователей по трафику (таблица, где раньше у тебя всё ехало)
func addTopUsers(pdf *gofpdf.Fpdf, kpi metrics.MetricsKPI, users []metrics.AnalyticsUserTraffic, durations []metrics.AnalyticsUserDuration) {
	if len(users) == 0 {
		return
	}

	totalBytes := kpi.TotalBytesIn + kpi.TotalBytesOut

	headers := []string{"#", "Пользователь", "Сессий", "Трафик (GiB)", "Доля трафика (%)", "Сред. длит. (мин)"}
	// Ширины подобраны так, чтобы всё аккуратно влезало на 180 мм (A4 с полями 15 мм)
	widths := []float64{10, 70, 20, 32, 23, 25}

	headerRow := func() {
		addSectionHeader(pdf, "Топ пользователей по трафику", "Лидеры по объёму переданных данных")
		renderTableHeader(pdf, headers, widths)
	}

	pdf.AddPage()
	addTopBand(pdf)
	headerRow()

	for idx, u := range users {
		ensureTableRowSpace(pdf, tableRowHeight, headerRow)
		fill := idx%2 == 0

		durationMinutes := lookupAvgDuration(u.Username, u.CommonName, durations)
		userLabel := formatUserLabel(u.Username, u.CommonName)

		userBytes := u.BytesIn + u.BytesOut
		sharePercent := 0.0
		if totalBytes > 0 {
			sharePercent = (float64(userBytes) / float64(totalBytes)) * 100.0
		}

		highlight := idx < 3

		drawTableRow(pdf, widths, []string{
			fmt.Sprintf("%d", idx+1),
			userLabel,
			fmt.Sprintf("%d", u.Sessions),
			formatGiB(userBytes),
			formatPercent(sharePercent),
			fmt.Sprintf("%.1f", durationMinutes),
		}, fill, highlight, nil)
	}
}

// Топ пользователей по суммарному времени
func addTopUsersByDuration(pdf *gofpdf.Fpdf, durations []metrics.AnalyticsUserDuration) {
	if len(durations) == 0 {
		return
	}

	headers := []string{"#", "Пользователь", "Сессий", "Суммарно (часы)", "Сред. сессия (мин)"}
	widths := []float64{10, 80, 20, 35, 35}

	headerRow := func() {
		addSectionHeader(pdf, "Топ пользователей по времени в VPN", "Пользователи с наибольшим суммарным временем подключения")
		renderTableHeader(pdf, headers, widths)
	}

	pdf.AddPage()
	addTopBand(pdf)
	headerRow()

	for idx, d := range durations {
		ensureTableRowSpace(pdf, tableRowHeight, headerRow)
		fill := idx%2 == 0
		userLabel := formatUserLabel(d.Username, d.CommonName)

		totalHours := float64(d.TotalDurationSec) / 3600.0
		avgMinutes := float64(0)
		if d.Sessions > 0 {
			avgMinutes = float64(d.TotalDurationSec) / float64(d.Sessions) / 60.0
		}

		highlight := idx < 3

		drawTableRow(pdf, widths, []string{
			fmt.Sprintf("%d", idx+1),
			userLabel,
			fmt.Sprintf("%d", d.Sessions),
			fmt.Sprintf("%.1f", totalHours),
			fmt.Sprintf("%.1f", avgMinutes),
		}, fill, highlight, nil)
	}
}

func addTopClients(pdf *gofpdf.Fpdf, kpi metrics.MetricsKPI, clients []metrics.TopClientPoint) {
	if len(clients) == 0 {
		return
	}

	totalBytes := kpi.TotalBytesIn + kpi.TotalBytesOut

	headers := []string{"#", "Common Name", "Трафик (GiB)", "Доля трафика (%)", "Статус"}
	widths := []float64{10, 70, 35, 30, 35}

	headerRow := func() {
		addSectionHeader(pdf, "Топ клиентов по трафику", "Клиенты, передавшие максимальный объём данных")
		renderTableHeader(pdf, headers, widths)
	}

	pdf.AddPage()
	addTopBand(pdf)
	headerRow()

	for idx, c := range clients {
		ensureTableRowSpace(pdf, tableRowHeight, headerRow)
		fill := idx%2 == 0

		status := "Был активен в периоде"
		statusColor := &[3]int{97, 97, 97}
		if c.ActiveNow {
			status = "Активен в периоде"
			statusColor = &[3]int{46, 125, 50}
		}

		sharePercent := 0.0
		if totalBytes > 0 {
			sharePercent = (float64(c.TotalBytes) / float64(totalBytes)) * 100.0
		}

		highlight := idx < 3

		drawTableRow(pdf, widths, []string{
			fmt.Sprintf("%d", idx+1),
			c.CommonName,
			formatGiB(c.TotalBytes),
			formatPercent(sharePercent),
			status,
		}, fill, highlight, statusColor)
	}
}

func addSecuritySection(pdf *gofpdf.Fpdf, stats metrics.MFAStats, authMethods []metrics.AuthMethodStat) {
	if stats.TotalSessions == 0 && len(authMethods) == 0 {
		return
	}

	headerRow := func() {
		addSectionHeader(pdf, "Безопасность и MFA", "Зрелость аутентификации и MFA за период")
		renderTableHeader(pdf, []string{"Показатель", "Значение"}, []float64{90, 90})
	}

	pdf.AddPage()
	addTopBand(pdf)
	headerRow()

	mfaShare := percentOf(stats.MFASessions, stats.TotalSessions)
	mfaSuccessShare := percentOf(stats.MFASuccess, stats.MFASessions)
	mfaFailedShare := percentOf(stats.MFAFailed, stats.MFASessions)

	mfaRows := [][]string{
		{"Всего сессий", fmt.Sprintf("%d", stats.TotalSessions)},
		{"Сессий с MFA", fmt.Sprintf("%d", stats.MFASessions)},
		{"Доля сессий с MFA (%)", formatPercent(mfaShare)},
		{"Успешных MFA", fmt.Sprintf("%d (%.1f%%)", stats.MFASuccess, mfaSuccessShare)},
		{"Неуспешных MFA", fmt.Sprintf("%d (%.1f%%)", stats.MFAFailed, mfaFailedShare)},
	}

	for idx, row := range mfaRows {
		ensureTableRowSpace(pdf, tableRowHeight, headerRow)
		drawTableRow(pdf, []float64{90, 90}, row, idx%2 == 0, false, nil)
	}

	if len(authMethods) == 0 {
		return
	}

	pdf.Ln(6)
	authHeaders := []string{"#", "Метод аутентификации", "Сессий", "Доля сессий (%)"}
	authWidths := []float64{10, 90, 30, 40}

	authHeaderRow := func() {
		addSectionHeader(pdf, "Топ методов аутентификации", "Использование auth backends")
		renderTableHeader(pdf, authHeaders, authWidths)
	}

	authHeaderRow()
	totalSessions := stats.TotalSessions
	for idx, m := range authMethods {
		ensureTableRowSpace(pdf, tableRowHeight, authHeaderRow)
		share := percentOf(m.Count, totalSessions)
		drawTableRow(pdf, authWidths, []string{
			fmt.Sprintf("%d", idx+1),
			truncateCellText(pdf, m.Method, authWidths[1]-2),
			fmt.Sprintf("%d", m.Count),
			formatPercent(share),
		}, idx%2 == 0, idx < 3, nil)
	}
}

func addDeviceProfileSection(pdf *gofpdf.Fpdf, totalSessions int64, osDistribution []metrics.AnalyticsKV, deviceTypes []metrics.DeviceTypeStat, clientApps []metrics.ClientAppStat) {
	if len(osDistribution) == 0 && len(deviceTypes) == 0 && len(clientApps) == 0 {
		return
	}

	pdf.AddPage()
	addTopBand(pdf)

	sectionHeader := func() {
		addSectionHeader(pdf, "Профиль устройств и клиентов", "Операционные системы, типы устройств и VPN-клиенты")
	}

	osHeaders := []string{"#", "Операционная система", "Сессий", "Доля сессий (%)"}
	osWidths := []float64{10, 90, 30, 40}
	osHeaderRow := func() {
		sectionHeader()
		renderTableHeader(pdf, osHeaders, osWidths)
	}

	if len(osDistribution) > 0 {
		osHeaderRow()
		osTotal := sumKV(osDistribution)
		for idx, os := range osDistribution {
			ensureTableRowSpace(pdf, tableRowHeight, osHeaderRow)
			share := percentOf(os.Value, osTotal)
			drawTableRow(pdf, osWidths, []string{
				fmt.Sprintf("%d", idx+1),
				truncateCellText(pdf, os.Key, osWidths[1]-2),
				fmt.Sprintf("%d", os.Value),
				formatPercent(share),
			}, idx%2 == 0, idx < 3, nil)
		}
	}

	if len(deviceTypes) > 0 {
		pdf.Ln(6)
		dtHeaders := []string{"Тип устройства", "Сессий", "Доля (%)"}
		dtWidths := []float64{90, 30, 40}
		dtHeaderRow := func() {
			addSectionHeader(pdf, "Типы устройств", "Desktop / mobile / other")
			renderTableHeader(pdf, dtHeaders, dtWidths)
		}

		dtHeaderRow()
		dtTotal := totalSessions
		if dtTotal == 0 {
			dtTotal = sumDeviceTypes(deviceTypes)
		}
		for idx, d := range deviceTypes {
			ensureTableRowSpace(pdf, tableRowHeight, dtHeaderRow)
			share := percentOf(d.Count, dtTotal)
			drawTableRow(pdf, dtWidths, []string{
				formatDeviceType(d.Type),
				fmt.Sprintf("%d", d.Count),
				formatPercent(share),
			}, idx%2 == 0, idx < 2, nil)
		}
	}

	if len(clientApps) > 0 {
		pdf.Ln(6)
		appHeaders := []string{"#", "Клиентское приложение", "Сессий", "Доля (%)"}
		appWidths := []float64{10, 95, 30, 35}
		appHeaderRow := func() {
			addSectionHeader(pdf, "VPN-клиенты", "Какое ПО используют пользователи")
			renderTableHeader(pdf, appHeaders, appWidths)
		}

		appHeaderRow()
		appTotal := totalSessions
		if appTotal == 0 {
			appTotal = sumClientApps(clientApps)
		}
		for idx, app := range clientApps {
			ensureTableRowSpace(pdf, tableRowHeight, appHeaderRow)
			share := percentOf(app.Count, appTotal)
			drawTableRow(pdf, appWidths, []string{
				fmt.Sprintf("%d", idx+1),
				truncateCellText(pdf, app.App, appWidths[1]-2),
				fmt.Sprintf("%d", app.Count),
				formatPercent(share),
			}, idx%2 == 0, idx < 3, nil)
		}
	}
}

func addCryptoAndCountrySection(pdf *gofpdf.Fpdf, ciphers []metrics.AnalyticsKV, countries []metrics.AnalyticsKV) {
	if len(ciphers) == 0 && len(countries) == 0 {
		return
	}

	pdf.AddPage()
	addTopBand(pdf)

	sectionHeader := func(title string, subtitle string) {
		addSectionHeader(pdf, title, subtitle)
	}

	if len(ciphers) > 0 {
		headers := []string{"#", "Шифр", "Сессий", "Доля (%)"}
		widths := []float64{10, 90, 30, 40}
		headerRow := func() {
			sectionHeader("Криптография", "Выбор шифров при подключении")
			renderTableHeader(pdf, headers, widths)
		}

		headerRow()
		total := sumKV(ciphers)
		for idx, c := range ciphers {
			ensureTableRowSpace(pdf, tableRowHeight, headerRow)
			share := percentOf(c.Value, total)
			drawTableRow(pdf, widths, []string{
				fmt.Sprintf("%d", idx+1),
				truncateCellText(pdf, c.Key, widths[1]-2),
				fmt.Sprintf("%d", c.Value),
				formatPercent(share),
			}, idx%2 == 0, idx < 3, nil)
		}
	}

	if len(countries) > 0 {
		if len(ciphers) > 0 {
			pdf.Ln(6)
		}
		headers := []string{"#", "Страна", "Сессий", "Доля (%)"}
		widths := []float64{10, 90, 30, 40}
		headerRow := func() {
			sectionHeader("Страны подключений", "География пользователей")
			renderTableHeader(pdf, headers, widths)
		}

		topN := countries
		if len(topN) > 10 {
			topN = topN[:10]
		}

		headerRow()
		total := sumKV(countries)
		for idx, c := range topN {
			ensureTableRowSpace(pdf, tableRowHeight, headerRow)
			share := percentOf(c.Value, total)
			drawTableRow(pdf, widths, []string{
				fmt.Sprintf("%d", idx+1),
				truncateCellText(pdf, c.Key, widths[1]-2),
				fmt.Sprintf("%d", c.Value),
				formatPercent(share),
			}, idx%2 == 0, idx < 3, nil)
		}
	}
}

func addProblemClientsSection(pdf *gofpdf.Fpdf, clients []metrics.ProblemClientRow) {
	if len(clients) == 0 {
		return
	}

	broaderHeader := func() {
		addSectionHeader(pdf, "Надёжность и проблемные клиенты", "Повторные переподключения и сбои")
		renderTableHeader(pdf, []string{"#", "Пользователь", "CN", "Сессий", "Переподкл.", "Трафик (GiB)", "Ср. длит. (мин)", "Последний IP", "Последняя активность"}, []float64{8, 30, 28, 15, 18, 22, 20, 18, 21})
	}

	pdf.AddPage()
	addTopBand(pdf)
	broaderHeader()

	for idx, c := range clients {
		ensureTableRowSpace(pdf, tableRowHeight, broaderHeader)
		trafficGiB := formatGiB(uint64(max64(c.TotalBytes, 0)))
		avgMinutes := formatMinutes(float64(c.AvgDurationSec))
		lastSeen := formatTimestamp(c.LastSeen)
		drawTableRow(pdf, []float64{8, 30, 28, 15, 18, 22, 20, 18, 21}, []string{
			fmt.Sprintf("%d", idx+1),
			truncateCellText(pdf, c.Username, 29),
			truncateCellText(pdf, c.CommonName, 27),
			fmt.Sprintf("%d", c.Sessions),
			fmt.Sprintf("%d", c.Reconnects),
			trafficGiB,
			avgMinutes,
			truncateCellText(pdf, c.LastIP, 17),
			lastSeen,
		}, idx%2 == 0, idx < 3, nil)
	}
}

func addDurationAndUsagePatternsSection(pdf *gofpdf.Fpdf, totalSessions int64, buckets []metrics.AnalyticsBucket, heatmap []metrics.UsageHeatmapCell, events []metrics.EventsTimelinePoint) {
	if len(buckets) == 0 && len(heatmap) == 0 && len(events) == 0 {
		return
	}

	pdf.AddPage()
	addTopBand(pdf)

	sectionHeader := func(title, subtitle string) {
		addSectionHeader(pdf, title, subtitle)
	}

	if len(buckets) > 0 {
		headers := []string{"Диапазон", "Сессий", "Доля (%)"}
		widths := []float64{90, 30, 40}
		headerRow := func() {
			sectionHeader("Продолжительность сессий", "Распределение по временным корзинам")
			renderTableHeader(pdf, headers, widths)
		}

		headerRow()
		total := totalSessions
		if total == 0 {
			total = sumBuckets(buckets)
		}
		for idx, b := range buckets {
			ensureTableRowSpace(pdf, tableRowHeight, headerRow)
			share := percentOf(b.Count, total)
			drawTableRow(pdf, widths, []string{
				truncateCellText(pdf, b.Label, widths[0]-2),
				fmt.Sprintf("%d", b.Count),
				formatPercent(share),
			}, idx%2 == 0, idx < 2, nil)
		}
	}

	if len(heatmap) > 0 {
		pdf.Ln(6)
		headers := []string{"#", "День недели", "Час", "Сессий"}
		widths := []float64{10, 60, 40, 30}

		headerRow := func() {
			sectionHeader("Пиковые временные слоты", "Топ-10 часов по активности")
			renderTableHeader(pdf, headers, widths)
		}

		sorted := append([]metrics.UsageHeatmapCell(nil), heatmap...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Sessions > sorted[j].Sessions })
		if len(sorted) > 10 {
			sorted = sorted[:10]
		}

		headerRow()
		for idx, cell := range sorted {
			ensureTableRowSpace(pdf, tableRowHeight, headerRow)
			day := weekdayLabel(cell.Weekday)
			hour := fmt.Sprintf("%02d:00–%02d:00", cell.Hour, (cell.Hour+1)%24)
			drawTableRow(pdf, widths, []string{
				fmt.Sprintf("%d", idx+1),
				day,
				hour,
				fmt.Sprintf("%d", cell.Sessions),
			}, idx%2 == 0, idx < 3, nil)
		}
	}

	if len(events) > 0 {
		pdf.Ln(6)
		headers := []string{"#", "Временной интервал", "Подключений", "Отключений"}
		widths := []float64{10, 70, 35, 35}

		headerRow := func() {
			sectionHeader("События подключений", "Интервалы с наибольшим числом коннектов")
			renderTableHeader(pdf, headers, widths)
		}

		sorted := append([]metrics.EventsTimelinePoint(nil), events...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Connects > sorted[j].Connects })
		if len(sorted) > 10 {
			sorted = sorted[:10]
		}

		headerRow()
		for idx, e := range sorted {
			ensureTableRowSpace(pdf, tableRowHeight, headerRow)
			interval := formatTimeInterval(e.Ts)
			drawTableRow(pdf, widths, []string{
				fmt.Sprintf("%d", idx+1),
				interval,
				fmt.Sprintf("%d", e.Connects),
				fmt.Sprintf("%d", e.Disconnects),
			}, idx%2 == 0, idx < 3, nil)
		}
	}
}

func renderTableHeader(pdf *gofpdf.Fpdf, headers []string, widths []float64) {
	pdf.SetFillColor(240, 242, 245)
	pdf.SetTextColor(60, 60, 60)
	pdf.SetDrawColor(220, 220, 220)
	pdf.SetFont(baseFont, "B", 10)
	for i, h := range headers {
		pdf.CellFormat(widths[i], tableRowHeight, h, "1", 0, "C", true, 0, "")
	}
	pdf.Ln(0)
	pdf.SetFont(baseFont, "", 9)
	pdf.SetTextColor(30, 30, 30)
}

func drawTableRow(pdf *gofpdf.Fpdf, widths []float64, cells []string, fill bool, emphasize bool, statusColor *[3]int) {
	if emphasize {
		pdf.SetFillColor(232, 240, 252)
	} else if fill {
		pdf.SetFillColor(245, 245, 245)
	} else {
		pdf.SetFillColor(255, 255, 255)
	}

	fontStyle := ""
	fontSize := 9.0
	if emphasize {
		fontStyle = "B"
		fontSize = 10.0
	}

	pdf.SetFont(baseFont, fontStyle, fontSize)
	defaultTextColor := [3]int{30, 30, 30}

	isNumericCell := func(s string) bool {
		hasDigit := false
		for _, r := range s {
			switch {
			case unicode.IsDigit(r):
				hasDigit = true
			case r == '.' || r == ',' || r == ' ' || r == '%' || r == '-' || unicode.IsLetter(r):
				continue
			default:
				return false
			}
		}
		return hasDigit
	}

	for i, cell := range cells {
		align := "L"
		if i == 0 {
			align = "C"
		} else if isNumericCell(cell) {
			align = "R"
		}

		if statusColor != nil && i == len(cells)-1 {
			pdf.SetTextColor(statusColor[0], statusColor[1], statusColor[2])
		}

		useFill := fill || emphasize
		pdf.CellFormat(widths[i], tableRowHeight, cell, "1", 0, align, useFill, 0, "")

		if statusColor != nil && i == len(cells)-1 {
			pdf.SetTextColor(defaultTextColor[0], defaultTextColor[1], defaultTextColor[2])
		}
	}

	pdf.Ln(0)
	pdf.SetFont(baseFont, "", 9)
	pdf.SetTextColor(defaultTextColor[0], defaultTextColor[1], defaultTextColor[2])
}

func truncateCellText(pdf *gofpdf.Fpdf, text string, maxWidth float64) string {
	if text == "" {
		return "—"
	}

	if pdf.GetStringWidth(text) <= maxWidth {
		return text
	}

	ellipsis := "…"
	available := maxWidth - pdf.GetStringWidth(ellipsis)
	if available <= 0 {
		return ellipsis
	}

	runes := []rune(text)
	res := make([]rune, 0, len(runes))
	for _, r := range runes {
		candidate := string(append(res, r))
		if pdf.GetStringWidth(candidate) > available {
			break
		}
		res = append(res, r)
	}

	return string(res) + ellipsis
}

func percentOf(part int64, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return (float64(part) / float64(total)) * 100
}

func sumKV(items []metrics.AnalyticsKV) int64 {
	var total int64
	for _, item := range items {
		total += item.Value
	}
	return total
}

func sumDeviceTypes(items []metrics.DeviceTypeStat) int64 {
	var total int64
	for _, item := range items {
		total += item.Count
	}
	return total
}

func sumClientApps(items []metrics.ClientAppStat) int64 {
	var total int64
	for _, item := range items {
		total += item.Count
	}
	return total
}

func sumBuckets(items []metrics.AnalyticsBucket) int64 {
	var total int64
	for _, item := range items {
		total += item.Count
	}
	return total
}

func formatDeviceType(t string) string {
	switch t {
	case "desktop":
		return "Desktop"
	case "mobile":
		return "Mobile"
	case "other":
		return "Other"
	default:
		return t
	}
}

func weekdayLabel(weekday int) string {
	labels := []string{"Вс", "Пн", "Вт", "Ср", "Чт", "Пт", "Сб"}
	if weekday < 0 || weekday >= len(labels) {
		return "—"
	}
	return labels[weekday]
}

func formatTimeInterval(ts int64) string {
	if ts <= 0 {
		return "—"
	}
	t := time.Unix(ts, 0).UTC()
	end := t.Add(30 * time.Minute)
	return fmt.Sprintf("%s – %s", t.Format("2006-01-02 15:04"), end.Format("15:04"))
}

func formatTimestamp(ts int64) string {
	if ts <= 0 {
		return "—"
	}
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04")
}

func max64(a int64, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func lookupAvgDuration(username, cn string, durations []metrics.AnalyticsUserDuration) float64 {
	for _, d := range durations {
		if d.Username == username && d.CommonName == cn {
			if d.Sessions == 0 {
				return 0
			}
			// минуты
			return float64(d.TotalDurationSec) / float64(d.Sessions) / 60.0
		}
	}
	return 0
}

func formatUserLabel(username, cn string) string {
	u := username
	if u == "" || u == "UNDEF" {
		u = ""
	}

	c := cn

	switch {
	case u == "" && c == "":
		return "—"
	case u == "" && c != "":
		return c
	case c == "" && u != "":
		return u
	case u == c:
		return u
	default:
		return fmt.Sprintf("%s (%s)", u, c)
	}
}

func formatGiB(bytes uint64) string {
	if bytes == 0 {
		return "0.00"
	}
	val := bytesToGiB(bytes)
	return fmt.Sprintf("%.2f", val)
}

func bytesToGiB(bytes uint64) float64 {
	if bytes == 0 {
		return 0
	}
	return float64(bytes) / 1024.0 / 1024.0 / 1024.0
}

func formatMinutes(sec float64) string {
	if sec <= 0 {
		return "0.0"
	}
	val := sec / 60.0
	return fmt.Sprintf("%.1f", val)
}

func formatPercent(p float64) string {
	if p <= 0 {
		return "0.0"
	}
	return fmt.Sprintf("%.1f", p)
}

func safeDateLabel(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func formatDate(t time.Time) string {
	return t.Format("2006-01-02")
}
