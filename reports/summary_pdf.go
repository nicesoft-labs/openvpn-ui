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
