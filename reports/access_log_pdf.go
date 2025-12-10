package reports

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/d3vilh/openvpn-ui/metrics"
	"github.com/jung-kurt/gofpdf"
)

// AccessLogFilters describes selected filters for PDF export.
type AccessLogFilters struct {
	From       string
	To         string
	EventType  string
	CommonName string
	TrustedIP  string
	VPNIP      string
}

// GenerateAccessLogPDF renders filtered access log as PDF table.
func GenerateAccessLogPDF(events []metrics.AnalyticsEventRow, filters AccessLogFilters, w io.Writer) error {
	pdf := newReport()
	if err := registerFonts(pdf); err != nil {
		return err
	}

	pdf.AliasNbPages("")
	pdf.AddPage()
	addAccessLogHeader(pdf, filters)
	addAccessLogTable(pdf, events)

	if pdf.Err() {
		return pdf.Error()
	}

	return pdf.Output(w)
}

func addAccessLogHeader(pdf *gofpdf.Fpdf, filters AccessLogFilters) {
	pdf.SetFont(baseFont, "B", 16)
	pdf.Cell(0, 10, "Журнал доступа")
	pdf.Ln(8)

	pdf.SetFont(baseFont, "", 11)
	pdf.SetTextColor(70, 70, 70)
	pdf.Cell(0, 7, fmt.Sprintf("Сгенерировано: %s", time.Now().Format(time.RFC3339)))
	pdf.Ln(8)

	pdf.SetFont(baseFont, "", 10)
	pdf.SetTextColor(40, 40, 40)
	pdf.Cell(0, 7, "Использованные фильтры:")
	pdf.Ln(6)

	if filters.From != "" || filters.To != "" {
		pdf.Cell(0, 6, fmt.Sprintf("• Время: %s — %s", valueOrDash(filters.From), valueOrDash(filters.To)))
		pdf.Ln(6)
	}
	if filters.EventType != "" {
		pdf.Cell(0, 6, fmt.Sprintf("• Событие: %s", filters.EventType))
		pdf.Ln(6)
	}
	if filters.CommonName != "" {
		pdf.Cell(0, 6, fmt.Sprintf("• CN: %s", filters.CommonName))
		pdf.Ln(6)
	}
	if filters.TrustedIP != "" {
		pdf.Cell(0, 6, fmt.Sprintf("• Внешний IP: %s", filters.TrustedIP))
		pdf.Ln(6)
	}
	if filters.VPNIP != "" {
		pdf.Cell(0, 6, fmt.Sprintf("• VPN IP: %s", filters.VPNIP))
		pdf.Ln(6)
	}

	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(2)
}

func addAccessLogTable(pdf *gofpdf.Fpdf, events []metrics.AnalyticsEventRow) {
	headers := []string{"Время", "Событие", "Пользователь", "CN", "Внешний IP", "VPN IP", "ОС / клиент", "Трафик", "Длительность"}
	widths := []float64{32, 22, 28, 28, 28, 24, 28, 18, 18}

	pdf.SetFont(baseFont, "B", 9)
	for i, h := range headers {
		pdf.CellFormat(widths[i], tableRowHeight, h, "1", 0, "L", false, 0, "")
	}
	pdf.Ln(-1)

	pdf.SetFont(baseFont, "", 8)
	for _, e := range events {
		pdf.CellFormat(widths[0], tableRowHeight, e.EventTime.Format("2006-01-02 15:04"), "1", 0, "L", false, 0, "")
		pdf.CellFormat(widths[1], tableRowHeight, e.EventType, "1", 0, "L", false, 0, "")
		pdf.CellFormat(widths[2], tableRowHeight, valueOrDash(e.Username), "1", 0, "L", false, 0, "")
		pdf.CellFormat(widths[3], tableRowHeight, valueOrDash(e.CommonName), "1", 0, "L", false, 0, "")
		pdf.CellFormat(widths[4], tableRowHeight, valueOrDash(e.TrustedIP), "1", 0, "L", false, 0, "")
		pdf.CellFormat(widths[5], tableRowHeight, valueOrDash(e.VPNIP), "1", 0, "L", false, 0, "")
		pdf.CellFormat(widths[6], tableRowHeight, valueOrDash(e.DeviceOS), "1", 0, "L", false, 0, "")
		pdf.CellFormat(widths[7], tableRowHeight, formatBytesMB(e.BytesIn+e.BytesOut), "1", 0, "L", false, 0, "")
		pdf.CellFormat(widths[8], tableRowHeight, formatDurationMinutes(e.DurationSec), "1", 0, "L", false, 0, "")
		pdf.Ln(-1)
	}
}

func valueOrDash(val string) string {
	if strings.TrimSpace(val) == "" {
		return "—"
	}
	return val
}

func formatBytesMB(total uint64) string {
	if total == 0 {
		return "—"
	}
	mb := float64(total) / 1024.0 / 1024.0
	return fmt.Sprintf("%.1f MB", mb)
}

func formatDurationMinutes(sec int64) string {
	if sec <= 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f мин", float64(sec)/60.0)
}
