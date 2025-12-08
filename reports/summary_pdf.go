package reports

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/d3vilh/openvpn-ui/metrics"
	"github.com/jung-kurt/gofpdf"
)

const (
	baseFont      = "DejaVuSans"
	primaryColorR = 34
	primaryColorG = 64
	primaryColorB = 120
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

	addTitlePage(pdf, from, to)
	addKPISummary(pdf, kpi)
	addSessionsByDay(pdf, sessionsByDay)
	addTopUsers(pdf, topUsersByTraffic, topUsersByDuration)
	addTopClients(pdf, topClientsByTraffic)

	if err := pdf.Err(); err != nil {
		return err
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
	if err := pdf.Err(); err != nil {
		return fmt.Errorf("failed to add font %s: %w", regular, err)
	}

	pdf.AddUTF8Font(baseFont, "B", bold)
	if err := pdf.Err(); err != nil {
		return fmt.Errorf("failed to add font %s: %w", bold, err)
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
	pdf.MultiCell(0, 7, "Отчёт предназначен для руководителей и отражает базовые показатели использования VPN. Отражены ключевые показатели, динамика по дням, а также топ пользователей и клиентов по трафику за выбранный период.", "", "L", false)

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
}

func ensureTableRowSpace(pdf *gofpdf.Fpdf, rowHeight float64, header func()) {
	_, y := pdf.GetXY()
	_, pageH := pdf.GetPageSize()
	_, _, _, bottomMargin := pdf.GetMargins()
	if y+rowHeight+bottomMargin > pageH {
		pdf.AddPage()
		header()
	}
}

func addKPISummary(pdf *gofpdf.Fpdf, kpi metrics.MetricsKPI) {
	pdf.AddPage()
	addSectionHeader(pdf, "Ключевые показатели за период", "Основные метрики использования NiceVPN")

	cards := []struct {
		title string
		value string
	}{
		{"Всего сессий", fmt.Sprintf("%d", kpi.TotalSessions)},
		{"Уникальные пользователи", fmt.Sprintf("%d", kpi.UniqueUsers)},
		{"Суммарный трафик", fmt.Sprintf("%s GiB", formatGiB(int64(kpi.TotalBytesIn+kpi.TotalBytesOut)))},
		{"Средняя длительность сессии", fmt.Sprintf("%s мин", formatMinutes(int64(kpi.AvgSessionDurationSec)))},
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
		x := startX + float64(col)*(cardW+gapX)
		y := startY + float64(row)*(cardH+gapY)
		drawKPICard(pdf, x, y, cardW, cardH, card.title, card.value)
	}

	rows := (len(cards) + cols - 1) / cols
	pdf.SetY(startY + float64(rows)*(cardH+gapY) + 5)
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

func addSessionsByDay(pdf *gofpdf.Fpdf, stats []metrics.AnalyticsDayStat) {
	headers := []string{"Дата", "Сессии", "Трафик входящий (GiB)", "Трафик исходящий (GiB)", "Сред. длительность (мин)"}
	widths := []float64{32, 25, 48, 48, 45}

	sectionHeader := func() {
		addSectionHeader(pdf, "Сводка по дням", "Динамика сессий и трафика")
		renderTableHeader(pdf, headers, widths)
	}

	pdf.AddPage()
	sectionHeader()

	for idx, d := range stats {
		ensureTableRowSpace(pdf, 8, sectionHeader)
		fill := idx%2 == 0
		pdf.CellFormat(widths[0], 8, d.Date, "", 0, "L", fill, 0, "")
		pdf.CellFormat(widths[1], 8, fmt.Sprintf("%d", d.Sessions), "", 0, "R", fill, 0, "")
		pdf.CellFormat(widths[2], 8, formatGiB(int64(d.BytesIn)), "", 0, "R", fill, 0, "")
		pdf.CellFormat(widths[3], 8, formatGiB(int64(d.BytesOut)), "", 0, "R", fill, 0, "")
		pdf.CellFormat(widths[4], 8, formatMinutes(int64(d.AvgDurationSec)), "", 1, "R", fill, 0, "")
	}
}

func addTopUsers(pdf *gofpdf.Fpdf, users []metrics.AnalyticsUserTraffic, durations []metrics.AnalyticsUserDuration) {
	headers := []string{"#", "Пользователь", "CN", "Сессий", "Трафик (GiB)", "Сред. длительность (мин)"}
	widths := []float64{10, 45, 40, 25, 35, 40}

	sectionHeader := func() {
		addSectionHeader(pdf, "Топ пользователей по трафику", "Лидеры по объёму переданных данных")
		renderTableHeader(pdf, headers, widths)
	}

	pdf.AddPage()
	sectionHeader()

	for idx, u := range users {
		ensureTableRowSpace(pdf, 8, sectionHeader)
		fill := idx%2 == 0
		durationMinutes := lookupAvgDuration(u.Username, u.CommonName, durations)
		username := u.Username
		if username == "" || username == "UNDEF" {
			username = "—"
		}
		highlight := idx < 3
		drawTableRow(pdf, widths, []string{
			fmt.Sprintf("%d", idx+1),
			username,
			u.CommonName,
			fmt.Sprintf("%d", u.Sessions),
			formatGiB(int64(u.BytesIn + u.BytesOut)),
			formatMinutes(int64(durationMinutes * 60)),
		}, fill, highlight, nil)
	}
}

func addTopClients(pdf *gofpdf.Fpdf, clients []metrics.TopClientPoint) {
	headers := []string{"#", "Common Name", "Трафик (GiB)", "Статус"}
	widths := []float64{10, 70, 40, 60}

	sectionHeader := func() {
		addSectionHeader(pdf, "Топ клиентов по трафику", "Клиенты, передавшие максимальный объём данных")
		renderTableHeader(pdf, headers, widths)
	}

	pdf.AddPage()
	sectionHeader()

	for idx, c := range clients {
		ensureTableRowSpace(pdf, 8, sectionHeader)
		fill := idx%2 == 0
		status := "Был активен в периоде"
		statusColor := &[3]int{97, 97, 97}
		if c.ActiveNow {
			status = "Активен в периоде"
			statusColor = &[3]int{46, 125, 50}
		}
		drawTableRow(pdf, widths, []string{
			fmt.Sprintf("%d", idx+1),
			c.CommonName,
			formatGiB(int64(c.TotalBytes)),
			status,
		}, fill, idx < 3, statusColor)
	}
}

func renderTableHeader(pdf *gofpdf.Fpdf, headers []string, widths []float64) {
	pdf.SetFillColor(240, 242, 245)
	pdf.SetTextColor(60, 60, 60)
	pdf.SetDrawColor(220, 220, 220)
	pdf.SetFont(baseFont, "B", 11)
	for i, h := range headers {
		pdf.CellFormat(widths[i], 8, h, "", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)
	pdf.SetFont(baseFont, "", 10)
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
	fontSize := 10.0
	if emphasize {
		fontStyle = "B"
		fontSize = 11.0
	}

	pdf.SetFont(baseFont, fontStyle, fontSize)
	defaultTextColor := [3]int{30, 30, 30}
	for i, cell := range cells {
		align := "L"
		if i == 0 || i >= len(cells)-2 {
			align = "C"
		}
		if i >= len(cells)-2 {
			align = "R"
		}
		if i == len(cells)-1 && len(cells) == 4 {
			align = "L"
		}

		if statusColor != nil && i == len(cells)-1 {
			pdf.SetTextColor(statusColor[0], statusColor[1], statusColor[2])
		}

		pdf.CellFormat(widths[i], 8, cell, "", 0, align, true, 0, "")
		if statusColor != nil && i == len(cells)-1 {
			pdf.SetTextColor(defaultTextColor[0], defaultTextColor[1], defaultTextColor[2])
		}
	}
	pdf.Ln(-1)
	pdf.SetFont(baseFont, "", 10)
	pdf.SetTextColor(defaultTextColor[0], defaultTextColor[1], defaultTextColor[2])
}

func lookupAvgDuration(username, cn string, durations []metrics.AnalyticsUserDuration) float64 {
	for _, d := range durations {
		if d.Username == username && d.CommonName == cn {
			if d.Sessions == 0 {
				return 0
			}
			return float64(d.TotalDurationSec) / float64(d.Sessions) / 60.0
		}
	}
	return 0
}

func formatGiB(bytes int64) string {
	if bytes <= 0 {
		return "0.00"
	}
	val := float64(bytes) / 1024.0 / 1024.0 / 1024.0
	return fmt.Sprintf("%.2f", val)
}

func formatMinutes(sec int64) string {
	if sec <= 0 {
		return "0.0"
	}
	val := float64(sec) / 60.0
	return fmt.Sprintf("%.1f", val)
}

func formatDate(t time.Time) string {
	return t.Format("2006-01-02")
}
