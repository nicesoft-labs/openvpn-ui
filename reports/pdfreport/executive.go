package pdfreport

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/d3vilh/openvpn-ui/metrics"
	"github.com/jung-kurt/gofpdf"
)

// ExecutiveReportInput contains aggregated data for executive PDF report.
type ExecutiveReportInput struct {
	From time.Time
	To   time.Time

	KPI                 metrics.MetricsKPI
	SessionsByDay       []metrics.AnalyticsDayStat
	TopUsersByTraffic   []metrics.AnalyticsUserTraffic
	TopUsersByDuration  []metrics.AnalyticsUserDuration
	TopClientsByTraffic []metrics.TopClientPoint
}

// GenerateExecutiveReportPDF renders PDF report to writer.
func GenerateExecutiveReportPDF(ctx context.Context, store metrics.Store, in ExecutiveReportInput, w io.Writer) error {
	_ = ctx
	_ = store // reserved for future geo/departments enrichments

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("NiceVPN — VPN report", false)
	pdf.SetAuthor("NiceVPN UI", false)

	addTitlePage(pdf, in)
	addKPISummary(pdf, in)
	addSessionsByDay(pdf, in)
	addTopUsers(pdf, in)
	addTopClients(pdf, in)

	// TODO: add charts as vector graphics when metrics visualization is ready.

	return pdf.Output(w)
}

func addTitlePage(pdf *gofpdf.Fpdf, in ExecutiveReportInput) {
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 20)
	pdf.Cell(0, 12, "NiceVPN — Сводный отчёт по VPN за период")
	pdf.Ln(14)

	pdf.SetFont("Helvetica", "", 14)
	pdf.Cell(0, 10, fmt.Sprintf("Период: %s — %s", in.From.Format("2006-01-02"), in.To.Format("2006-01-02")))
	pdf.Ln(8)

	now := time.Now().UTC()
	pdf.SetFont("Helvetica", "", 12)
	pdf.Cell(0, 8, fmt.Sprintf("Время генерации (UTC): %s", now.Format(time.RFC3339)))
	pdf.Ln(6)
	pdf.Cell(0, 8, fmt.Sprintf("Время генерации (local): %s", now.Local().Format(time.RFC3339)))
	pdf.Ln(14)

	pdf.SetFont("Helvetica", "", 11)
	pdf.MultiCell(0, 7, "Отчёт предназначен для руководителей и отражает базовые показатели использования VPN. TODO: добавить разделение по регионам и отделам.", "", "L", false)
}

func addSectionHeader(pdf *gofpdf.Fpdf, title string) {
	pdf.SetFont("Helvetica", "B", 14)
	pdf.Cell(0, 10, title)
	pdf.Ln(10)
	pdf.SetFont("Helvetica", "", 11)
}

func addKPISummary(pdf *gofpdf.Fpdf, in ExecutiveReportInput) {
	pdf.AddPage()
	addSectionHeader(pdf, "Ключевые показатели за период")

	rows := [][]string{
		{"Всего сессий", fmt.Sprintf("%d", in.KPI.TotalSessions)},
		{"Уникальные пользователи", fmt.Sprintf("%d", in.KPI.UniqueUsers)},
		{"Суммарный трафик", fmt.Sprintf("%.2f GiB", toGiB(in.KPI.TotalBytesIn+in.KPI.TotalBytesOut))},
		{"Средняя длительность сессии", fmt.Sprintf("%.1f минут", in.KPI.AvgSessionDurationSec/60.0)},
	}

	if in.KPI.MaxConcurrentSessions > 0 {
		rows = append(rows, []string{"Максимум одновременных клиентов", fmt.Sprintf("%d", in.KPI.MaxConcurrentSessions)})
	} else {
		rows = append(rows, []string{"Максимум одновременных клиентов", "TODO"})
	}

	pdf.SetFillColor(245, 245, 245)
	for idx, row := range rows {
		fill := idx%2 == 0
		pdf.CellFormat(80, 8, row[0], "1", 0, "L", fill, 0, "")
		pdf.CellFormat(0, 8, row[1], "1", 1, "L", fill, 0, "")
	}
}

func addSessionsByDay(pdf *gofpdf.Fpdf, in ExecutiveReportInput) {
	pdf.AddPage()
	addSectionHeader(pdf, "Сводка по дням")

	headers := []string{"Дата", "Сессии", "Трафик (ГиБ вход)", "Трафик (ГиБ выход)", "Сред. длительность (мин)"}
	widths := []float64{32, 22, 40, 40, 45}

	pdf.SetFillColor(230, 230, 230)
	for i, h := range headers {
		pdf.CellFormat(widths[i], 8, h, "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	pdf.SetFillColor(245, 245, 245)
	for idx, d := range in.SessionsByDay {
		fill := idx%2 == 0
		pdf.CellFormat(widths[0], 8, d.Date, "1", 0, "L", fill, 0, "")
		pdf.CellFormat(widths[1], 8, fmt.Sprintf("%d", d.Sessions), "1", 0, "C", fill, 0, "")
		pdf.CellFormat(widths[2], 8, fmt.Sprintf("%.2f", toGiB(d.BytesIn)), "1", 0, "R", fill, 0, "")
		pdf.CellFormat(widths[3], 8, fmt.Sprintf("%.2f", toGiB(d.BytesOut)), "1", 0, "R", fill, 0, "")
		pdf.CellFormat(widths[4], 8, fmt.Sprintf("%.1f", d.AvgDurationSec/60.0), "1", 1, "R", fill, 0, "")
	}
}

func addTopUsers(pdf *gofpdf.Fpdf, in ExecutiveReportInput) {
	pdf.AddPage()
	addSectionHeader(pdf, "Топ пользователей по трафику")

	headers := []string{"#", "Пользователь", "CN", "Сессий", "Трафик (ГиБ)", "Сред. длительность (мин)"}
	widths := []float64{10, 45, 40, 25, 35, 40}

	pdf.SetFillColor(230, 230, 230)
	for i, h := range headers {
		pdf.CellFormat(widths[i], 8, h, "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	pdf.SetFillColor(245, 245, 245)
	for idx, u := range in.TopUsersByTraffic {
		fill := idx%2 == 0
		durationMinutes := lookupAvgDuration(u.Username, u.CommonName, in.TopUsersByDuration)
		pdf.CellFormat(widths[0], 8, fmt.Sprintf("%d", idx+1), "1", 0, "C", fill, 0, "")
		pdf.CellFormat(widths[1], 8, u.Username, "1", 0, "L", fill, 0, "")
		pdf.CellFormat(widths[2], 8, u.CommonName, "1", 0, "L", fill, 0, "")
		pdf.CellFormat(widths[3], 8, fmt.Sprintf("%d", u.Sessions), "1", 0, "C", fill, 0, "")
		pdf.CellFormat(widths[4], 8, fmt.Sprintf("%.2f", toGiB(u.BytesIn+u.BytesOut)), "1", 0, "R", fill, 0, "")
		pdf.CellFormat(widths[5], 8, fmt.Sprintf("%.1f", durationMinutes), "1", 1, "R", fill, 0, "")
	}
}

func addTopClients(pdf *gofpdf.Fpdf, in ExecutiveReportInput) {
	pdf.AddPage()
	addSectionHeader(pdf, "Топ клиентов по трафику")

	headers := []string{"#", "Common Name", "Трафик (ГиБ)", "Статус"}
	widths := []float64{10, 70, 40, 50}

	pdf.SetFillColor(230, 230, 230)
	for i, h := range headers {
		pdf.CellFormat(widths[i], 8, h, "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	pdf.SetFillColor(245, 245, 245)
	for idx, c := range in.TopClientsByTraffic {
		fill := idx%2 == 0
		status := "Активность в периоде"
		// TODO: enhance status detection using session timeline and geo info.
		pdf.CellFormat(widths[0], 8, fmt.Sprintf("%d", idx+1), "1", 0, "C", fill, 0, "")
		pdf.CellFormat(widths[1], 8, c.CommonName, "1", 0, "L", fill, 0, "")
		pdf.CellFormat(widths[2], 8, fmt.Sprintf("%.2f", toGiB(c.TotalBytes)), "1", 0, "R", fill, 0, "")
		pdf.CellFormat(widths[3], 8, status, "1", 1, "L", fill, 0, "")
	}
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

func toGiB(total uint64) float64 {
	return float64(total) / 1024.0 / 1024.0 / 1024.0
}
