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

const defaultRedirectGateway = "redirect-gateway def1 bypass-dhcp"

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

	// Загружаем текущие настройки
	cfg := models.OVConfig{Profile: "default"}
	_ = cfg.Read("Profile")

	logs.Info("Post: Parsing form data")
	logs.Info("Form data (raw): ", c.Ctx.Request.Form)

	// Парсим форму в cfg
	if err := c.ParseForm(&cfg); err != nil {
		logs.Warning(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
		return
	}

	normalizeStringFields(&cfg.Config)

	redirectGW, err := normalizeRedirectGW(cfg.Config.RedirectGW)
	if err != nil {
		logs.Warning(err)
		c.Ctx.Output.SetStatus(400)
		_, _ = c.Ctx.ResponseWriter.Write([]byte(err.Error()))
		return
	}

	if redirectGW != "" {
		cfg.Config.ForceDefaultRoute = true
	}
	cfg.Config.RedirectGW = redirectGW

	if cfg.Config.SplitOnlyMode && cfg.Config.ForceDefaultRoute {
		msg := "ForceDefaultRoute cannot be used together with SplitOnlyMode"
		logs.Warning(msg)
		c.Ctx.Output.SetStatus(400)
		_, _ = c.Ctx.ResponseWriter.Write([]byte(msg))
		return
	}

	// Строим итоговый набор push "route ..."
	pushRoutes, err := buildPushRoutes(cfg.Config.PushRoute, cfg.Config.PushRoutesExtra)
	if err != nil {
		logs.Warning(err)
		c.Ctx.Output.SetStatus(400)
		_, _ = c.Ctx.ResponseWriter.Write([]byte(err.Error()))
		return
	}

	cfg.Config.PushRoutes = strings.Join(pushRoutes, "\n")
	if cfg.Config.PushRoute != "" && len(pushRoutes) > 0 {
		// для обратной совместимости сохраняем первое значение в единичное поле
		cfg.Config.PushRoute = pushRoutes[0]
	}

	renderCfg := cfg.Config
	renderCfg.PushRoutes = strings.Join(pushRoutes, "\n")

	if renderCfg.SplitOnlyMode {
		renderCfg.RedirectGW = ""
		logs.Info("SplitOnlyMode is enabled: skipping redirect-gateway push")
	} else if renderCfg.ForceDefaultRoute {
		redirectValue := renderCfg.RedirectGW
		if redirectValue == "" {
			redirectValue = defaultRedirectGateway
		}
		renderCfg.RedirectGW = fmt.Sprintf("push \"%s\"", redirectValue)
	} else {
		renderCfg.RedirectGW = ""
	}

	logs.Info("Post: Dumping configuration data")
	lib.Dump(cfg)
	c.Data["Settings"] = &cfg
	logs.Info("Settings data attached to template")

	// Всегда прокидываем xsrfdata после submit
	c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())

	// Сохраняем server.conf по шаблону
	destPath := filepath.Join(state.GlobalCfg.OVConfigPath, "server.conf")
	tplPath := filepath.Join(c.ConfigDir, "openvpn-server-config.tpl")

	// ВАЖНО: тут было `err :=` — заменено на обычное присваивание `err =`
	err = config.SaveToFile(tplPath, renderCfg, destPath)
	if err != nil {
		logs.Warning(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
		return
	}

	// Обновляем запись в БД
	o := orm.NewOrm()
	if _, err := o.Update(&cfg); err != nil {
		flash.Error(err.Error())
	} else {
		flash.Success("Post: Config has been updated")
		// Пытаемся мягко перегрузить OpenVPN через management-interface
		client := mi.NewClient(state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress)
		if err := client.Signal("SIGTERM"); err != nil {
			flash.Warning("Config has been updated but OpenVPN server was NOT reloaded: " + err.Error())
		}
	}

	// Перечитываем сохранённый конфиг для модального окна
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

	if err := c.ParseForm(&cfg); err != nil {
		logs.Warning(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
		return
	}

	lib.Dump(cfg)
	c.Data["Settings"] = &cfg
	c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())

	destPath := filepath.Join(state.GlobalCfg.OVConfigPath, "server.conf")

	err := lib.ConfSaveToFile(destPath, c.GetString("ServerConfig"))
	if err != nil {
		logs.Error("Error saving server config to file:", err)
		flash.Error("Error saving server config to file")
		return
	} else {
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
	pushRouteRx          = regexp.MustCompile(`^(?:push\s+"?route|route)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})"?$`)
	pushRoutesExtraRx    = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$`)
	redirectGatewayRx    = regexp.MustCompile(`^(?:push\s+)?redirect-gateway(?:\s+([\w!\-\s]+))?$`)
	redirectGatewayAllow = map[string]struct{}{
		"def1":        {},
		"bypass-dhcp": {},
		"bypass-dns":  {},
		"local":       {},
		"autolocal":   {},
		"block-local": {},
		"ipv6":        {},
		"!ipv4":       {},
	}
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
			return nil, fmt.Errorf("invalid PushRoutesExtra line: %q, expected \"<NET> <MASK>\".", trimmed)
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
		return "", fmt.Errorf("invalid PushRoute line: %q, expected \"<NET> <MASK>\".", route)
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

func normalizeRedirectGW(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}

	matches := redirectGatewayRx.FindStringSubmatch(trimmed)
	if len(matches) == 0 {
		return "", fmt.Errorf("invalid RedirectGW value: %q, expected \"redirect-gateway [options]\".", value)
	}

	optionsRaw := ""
	if len(matches) > 1 {
		optionsRaw = strings.TrimSpace(matches[1])
	}
	if optionsRaw == "" {
		return "redirect-gateway", nil
	}

	seen := make(map[string]struct{})
	normalizedOpts := make([]string, 0)
	for _, opt := range strings.Fields(optionsRaw) {
		lowerOpt := strings.ToLower(opt)
		if _, ok := redirectGatewayAllow[lowerOpt]; !ok {
			return "", fmt.Errorf("invalid redirect-gateway option: %q", opt)
		}
		if _, exists := seen[lowerOpt]; !exists {
			seen[lowerOpt] = struct{}{}
			normalizedOpts = append(normalizedOpts, lowerOpt)
		}
	}

	if len(normalizedOpts) == 0 {
		return "redirect-gateway", nil
	}

	return fmt.Sprintf("redirect-gateway %s", strings.Join(normalizedOpts, " ")), nil
}

func normalizeStringFields(cfg *config.Config) {
	cfg.PushRoute = strings.TrimSpace(cfg.PushRoute)
	cfg.RedirectGW = strings.TrimSpace(cfg.RedirectGW)
	cfg.PushRoutesExtra = normalizeLineEndings(strings.TrimSpace(cfg.PushRoutesExtra))
	cfg.ScriptSecurity = strings.TrimSpace(cfg.ScriptSecurity)
	cfg.UserPassVerify = strings.TrimSpace(cfg.UserPassVerify)
	cfg.CustomOptOne = strings.TrimSpace(cfg.CustomOptOne)
	cfg.CustomOptTwo = strings.TrimSpace(cfg.CustomOptTwo)
	cfg.CustomOptThree = strings.TrimSpace(cfg.CustomOptThree)
}
