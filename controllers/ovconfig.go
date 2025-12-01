package controllers

import (
	"fmt"
	"html/template"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	"github.com/d3vilh/openvpn-server-config/server/config"
	mi "github.com/d3vilh/openvpn-server-config/server/mi"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/state"
)

type OVConfigController struct {
	BaseController
	ConfigDir string
}

func (c *OVConfigController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}
	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: "OpenVPN Server configuration",
	}
}

// @router /ov/config [Get]
func (c *OVConfigController) Get() {
	c.TplName = "ovconfig.html"
	besettings := models.Settings{Profile: "default"}
	_ = besettings.Read("Profile")
	c.Data["BeeSettings"] = &besettings

	destPath := filepath.Join(state.GlobalCfg.OVConfigPath, "server.conf")
	serverConf, err := os.ReadFile(destPath)
	if err != nil {
		logs.Error(err)
		return
	}
	c.Data["ServerConfig"] = string(serverConf)
	c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())
	cfg := models.OVConfig{Profile: "default"}
	_ = cfg.Read("Profile")
	c.Data["Settings"] = &cfg

}

// @router /ov/config [Post]
func (c *OVConfigController) Post() {
	logs.Info("Starting Post method in OVConfigController")

	c.TplName = "ovconfig.html"
	flash := web.NewFlash()
	cfg := models.OVConfig{Profile: "default"}
	_ = cfg.Read("Profile")

	logs.Info("Post: Parsing form data")
	logs.Info("Form data before parsing: %v", c.Ctx.Request.Form)
	if err := c.ParseForm(&cfg); err != nil {
		logs.Warning(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
		return
	}
	cfg.Config.PushRoute = strings.TrimSpace(cfg.Config.PushRoute)
	cfg.Config.RedirectGW = strings.TrimSpace(cfg.Config.RedirectGW)
	cfg.Config.PushRoutesExtra = normalizeLineEndings(strings.TrimSpace(cfg.Config.PushRoutesExtra))

	pushRoutes, err := buildPushRoutes(cfg.Config.PushRoute, cfg.Config.PushRoutesExtra)
	if err != nil {
		logs.Warning(err)
		c.Ctx.Output.SetStatus(400)
		_, _ = c.Ctx.ResponseWriter.Write([]byte(err.Error()))
		return
	}

	cfg.Config.PushRoutes = strings.Join(pushRoutes, "\n")
	if cfg.Config.PushRoute != "" && len(pushRoutes) > 0 {
		cfg.Config.PushRoute = pushRoutes[0]
	}

	if cfg.Config.SplitOnlyMode {
		cfg.Config.RedirectGW = ""
	}
	logs.Info("Form data after parsing: %v", c.Ctx.Request.Form)

	logs.Info("Post: Dumping configuration data")
	logs.Info("Configuration data: %v", cfg)
	lib.Dump(cfg)
	c.Data["Settings"] = &cfg
	logs.Info("Settings data: %v", c.Data["Settings"])

	destPath := filepath.Join(state.GlobalCfg.OVConfigPath, "server.conf")
	logs.Info("Post: Saving configuration to file according to template")
	err := config.SaveToFile(filepath.Join(c.ConfigDir, "openvpn-server-config.tpl"), cfg.Config, destPath)
	if err != nil {
		logs.Warning(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
		return
	}

	logs.Info("Post: Updating configuration in database")
	o := orm.NewOrm()
	if _, err := o.Update(&cfg); err != nil {
		flash.Error(err.Error())
	} else {
		flash.Success("Post: Config has been updated")
		client := mi.NewClient(state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress)
		if err := client.Signal("SIGTERM"); err != nil {
			flash.Warning("Config has been updated but OpenVPN server was NOT reloaded: " + err.Error())
		}
	}

	logs.Info("Post: Reading updated server configuration from file")
	serverConf, err := os.ReadFile(destPath)
	if err != nil {
		logs.Error("Error reading server config from file:", err)
		flash.Error("Error reading server config from file")
		return
	}
	c.Data["ServerConfig"] = string(serverConf)

	flash.Store(&c.Controller)
}

// @router /ov/config/edit [Edit]
func (c *OVConfigController) Edit() {
	c.TplName = "ovconfig.html"
	flash := web.NewFlash()
	cfg := models.OVConfig{Profile: "default"}
	_ = cfg.Read("Profile")

	//logs.Info("Post: Parsing form data")
	if err := c.ParseForm(&cfg); err != nil {
		logs.Warning(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
		return
	}

	//logs.Info("Post: Dumping configuration data")
	lib.Dump(cfg)
	c.Data["Settings"] = &cfg

	//logs.Info("Starting Edit method in OVConfigController")
	destPath := filepath.Join(state.GlobalCfg.OVConfigPath, "server.conf")

	err := lib.ConfSaveToFile(destPath, c.GetString("ServerConfig"))
	if err != nil {
		logs.Error("Error saving server config to file:", err)
		flash.Error("Error saving server config to file")
		return
	} else {
		//logs.Info("Edit: Server config saved to file:", destPath)
		flash.Success("Config has been updated")
	}

	serverConf, err := os.ReadFile(destPath)
	if err != nil {
		logs.Error("Error reading server config from file:", err)
		flash.Error("Error reading server config from file")
		return
	}
	c.Data["ServerConfig"] = string(serverConf)

	flash.Store(&c.Controller)
}

var (
	pushRouteRx       = regexp.MustCompile(`^(?:push\s+"?route|route)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})"?$`)
	pushRoutesExtraRx = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$`)
)

func buildPushRoutes(pushRoute string, pushRoutesExtra string) ([]string, error) {
	routes := make([]string, 0)
	seen := make(map[string]struct{})

	if trimmed := strings.TrimSpace(pushRoute); trimmed != "" {
		normalized, err := normalizePushRoute(trimmed)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized]; !ok {
			seen[normalized] = struct{}{}
			routes = append(routes, normalized)
		}
	}

	lines := strings.Split(pushRoutesExtra, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		m := pushRoutesExtraRx.FindStringSubmatch(trimmed)
		if m == nil || !isValidIPv4(m[1]) || !isValidIPv4(m[2]) {
			return nil, fmt.Errorf("invalid PushRoutesExtra line: \"%s\", expected \"<NET> <MASK>\".", trimmed)
		}

		normalized := fmt.Sprintf("push \"route %s %s\"", m[1], m[2])
		if _, ok := seen[normalized]; !ok {
			seen[normalized] = struct{}{}
			routes = append(routes, normalized)
		}
	}

	return routes, nil
}

func normalizePushRoute(route string) (string, error) {
	m := pushRouteRx.FindStringSubmatch(route)
	if m == nil || !isValidIPv4(m[1]) || !isValidIPv4(m[2]) {
		return "", fmt.Errorf("invalid PushRoute line: \"%s\", expected \"<NET> <MASK>\".", route)
	}

	return fmt.Sprintf("push \"route %s %s\"", m[1], m[2]), nil
}

func normalizeLineEndings(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return value
}

func isValidIPv4(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() != nil
}
