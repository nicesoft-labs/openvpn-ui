package controllers

import (
	"html/template"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	"github.com/nicesoft-labs/openvpn-ui/models"
	"github.com/nicesoft-labs/openvpn-ui/state"
)

type SettingsController struct {
	BaseController
	ConfigDir string
}

func (c *SettingsController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}
	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: "OpenVPN UI Settings",
	}
}

func (c *SettingsController) Get() {
	c.TplName = "settings.html"
	c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())
	settings := c.CurrentSettings
	if settings == nil {
		fallback := models.Settings{Profile: c.CurrentProfile}
		_ = fallback.Read("Profile")
		settings = &fallback
	}
	c.Data["Settings"] = settings
}

func (c *SettingsController) Post() {
	c.TplName = "settings.html"

	flash := web.NewFlash()
	action := c.GetString("action")

	switch action {
	case "create":
		newSettings := models.Settings{}
		if err := c.ParseForm(&newSettings); err != nil {
			logs.Warning(err)
			flash.Error(err.Error())
			break
		}
		if newSettings.Profile == "" {
			flash.Error("Profile name is required")
			break
		}

		if err := models.PrepareInstanceSettings(&newSettings, c.CurrentSettings.OVConfigPath, c.CurrentSettings.EasyRSAPath); err != nil {
			logs.Warning(err)
			flash.Error(err.Error())
			break
		}

		if _, err := orm.NewOrm().Insert(&newSettings); err != nil {
			flash.Error(err.Error())
			break
		}

		models.EnsureProfileConfigs(c.ConfigDir, &newSettings)
		c.CurrentProfile = newSettings.Profile
		c.CurrentSettings = &newSettings
		c.SetSession("profile", newSettings.Profile)
		flash.Success("New instance has been created and selected")
	default:
		settings := models.Settings{Profile: c.CurrentProfile}
		_ = settings.Read("Profile")
		if err := c.ParseForm(&settings); err != nil {
			logs.Warning(err)
			flash.Error(err.Error())
			flash.Store(&c.Controller)
			return
		}
		c.CurrentSettings = &settings
		c.Data["Settings"] = &settings

		o := orm.NewOrm()
		if _, err := o.Update(&settings); err != nil {
			flash.Error(err.Error())
		} else {
			flash.Success("Settings has been updated")
			state.GlobalCfg = settings
		}
	}

	flash.Store(&c.Controller)
	c.Get()
}
