package controllers

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/metrics"
	"github.com/d3vilh/openvpn-ui/reports"
)

// ReportsController handles VPN reports rendering and export.
type ReportsController struct {
	BaseController
}

// ReportsViewModel holds data for reports view.
type ReportsViewModel struct {
	MetricsEnabled  bool
	DataUnavailable bool

	// User input
	From         time.Time
	To           time.Time
	FromStr      string
	ToStr        string
	PeriodPreset string // "7d", "30d", "custom"
	ReportType   string // "executive"

	// Calculated KPI (without geo and departments)
	KPI metrics.MetricsKPI
}

// Get renders reports page.
func (c *ReportsController) Get() {
	if !c.IsLogin {
		c.Redirect(c.LoginPath(), 302)
		return
	}

	store := metrics.GetGlobalStore()
	vm := ReportsViewModel{}

	if store == nil {
		vm.MetricsEnabled = false
		c.Data["vm"] = vm
		c.Data["breadcrumbs"] = &BreadCrumbs{Title: "Reports"}
		c.TplName = "reports/index.html"
		return
	}

	vm.MetricsEnabled = true
	c.fillReportViewModel(&vm)

	ctx := context.Background()
	kpi, err := metrics.AggregateSessionsKPI(ctx, store, vm.From, vm.To)
	if err != nil {
		logs.Warn("metrics: reports kpi aggregation: %v", err)
		vm.DataUnavailable = true
	} else {
		vm.KPI = kpi
	}

	c.Data["vm"] = vm
	c.Data["breadcrumbs"] = &BreadCrumbs{Title: "Reports"}
	c.TplName = "reports/index.html"
}

// Download generates PDF report based on selected parameters.
func (c *ReportsController) Download() {
	if !c.IsLogin {
		c.Redirect(c.LoginPath(), 302)
		return
	}

	store := metrics.GetGlobalStore()
	if store == nil {
		c.Ctx.Output.SetStatus(503)
		c.Ctx.Output.Body([]byte("metrics store unavailable"))
		return
	}

	vm := ReportsViewModel{MetricsEnabled: true}
	c.fillReportViewModel(&vm)

	ctx := context.Background()
	buf := &bytes.Buffer{}
	if err := reports.GenerateSummaryPDF(ctx, store, vm.From, vm.To, buf); err != nil {
		logs.Error("reports: generate pdf: %v", err)
		c.Ctx.Output.SetStatus(500)
		c.Ctx.Output.Body([]byte("failed to generate report"))
		return
	}

	c.Ctx.Output.Header("Content-Type", "application/pdf")
	c.Ctx.Output.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"vpn-report-%s-%s.pdf\"", vm.From.Format("2006-01-02"), vm.To.Format("2006-01-02")))
	c.Ctx.Output.Body(buf.Bytes())
}

func (c *ReportsController) fillReportViewModel(vm *ReportsViewModel) {
	reportType := c.GetString("report_type", "executive")
	preset := c.GetString("preset", "7d")
	now := time.Now().UTC()

	vm.ReportType = reportType
	vm.PeriodPreset = preset

	if preset == "custom" {
		fromStr := c.GetString("from")
		toStr := c.GetString("to")
		from, errFrom := time.Parse("2006-01-02", fromStr)
		to, errTo := time.Parse("2006-01-02", toStr)
		if errFrom != nil || errTo != nil {
			preset = "7d"
			vm.PeriodPreset = preset
		} else {
			vm.From = from.UTC()
			vm.To = to.UTC()
			vm.FromStr = vm.From.Format("2006-01-02")
			vm.ToStr = vm.To.Format("2006-01-02")
			return
		}
	}

	switch preset {
	case "30d":
		vm.From = now.Add(-30 * 24 * time.Hour)
	default:
		vm.From = now.Add(-7 * 24 * time.Hour)
		vm.PeriodPreset = "7d"
	}
	vm.To = now
	vm.FromStr = vm.From.Format("2006-01-02")
	vm.ToStr = vm.To.Format("2006-01-02")
}
