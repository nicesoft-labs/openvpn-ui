package controllers

import (
	"html/template"
	"os"
	"path/filepath"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	easyrsaconfig "github.com/d3vilh/openvpn-server-config/easyrsa/config"
	mi "github.com/d3vilh/openvpn-server-config/server/mi"
	"github.com/nicesoft-labs/openvpn-ui/lib"
	"github.com/nicesoft-labs/openvpn-ui/models"
)

type EasyRSAConfigController struct {
	BaseController
	ConfigDir string
}

func (c *EasyRSAConfigController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}
	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: "EasyRSA vars",
	}
}

func (c *EasyRSAConfigController) Get() {
	c.TplName = "easyrsavar.html"

	destPathEasyRSAConfig := filepath.Join(c.CurrentSettings.EasyRSAPath, "pki/vars")
	easyRSAConfig, err := os.ReadFile(destPathEasyRSAConfig)
	if err != nil {
		logs.Error(err)
		return
	}
	c.Data["EasyRSAConf"] = string(easyRSAConfig)

	c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())
	cfg := models.EasyRSAConfig{Profile: c.CurrentProfile}
	_ = cfg.Read("Profile")
	c.Data["Settings"] = &cfg

}

func (c *EasyRSAConfigController) Post() {
	c.TplName = "easyrsavar.html"
	flash := web.NewFlash()
	cfg := models.EasyRSAConfig{Profile: c.CurrentProfile}
	if err := cfg.Read("Profile"); err != nil {
		cfg.Profile = c.CurrentProfile
	}
	if err := c.ParseForm(&cfg); err != nil {
		logs.Warning(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
		return
	}
	lib.Dump(cfg)
	c.Data["Settings"] = &cfg

	destPath := filepath.Join(c.CurrentSettings.EasyRSAPath, "pki/vars")
	err := easyrsaconfig.SaveToFile(filepath.Join(c.ConfigDir, "easyrsa-vars.tpl"), cfg.Config, destPath)
	if err != nil {
		logs.Warning(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
		return
	}

	destPath = filepath.Join(c.CurrentSettings.OVConfigPath, "config/easy-rsa.vars")
	err = easyrsaconfig.SaveToFile(filepath.Join(c.ConfigDir, "easyrsa-vars.tpl"), cfg.Config, destPath)
	if err != nil {
		logs.Warning(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
		return
	}

	o := orm.NewOrm()
	if _, err := o.Update(&cfg); err != nil {
		flash.Error(err.Error())
	} else {
		flash.Success("Config has been updated")
		client := mi.NewClient(c.CurrentSettings.MINetwork, c.CurrentSettings.MIAddress)
		if err := client.Signal("SIGTERM"); err != nil {
			flash.Warning("Config has been updated but OpenVPN server was NOT reloaded: " + err.Error())
		}
	}

	destPathEasyRSAConfig := filepath.Join(c.CurrentSettings.EasyRSAPath, "pki/vars")
	easyRSAConfig, err := os.ReadFile(destPathEasyRSAConfig)
	if err != nil {
		logs.Error(err)
		return
	}
	c.Data["EasyRSAConf"] = string(easyRSAConfig)

	flash.Store(&c.Controller)

}
