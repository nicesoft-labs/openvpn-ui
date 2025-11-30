package controllers

import (
	"github.com/beego/beego/v2/server/web"
	"github.com/nicesoft-labs/openvpn-ui/models"
	"github.com/nicesoft-labs/openvpn-ui/state"
)

type BaseController struct {
	web.Controller

	Userinfo *models.User
	IsLogin  bool

	CurrentProfile  string
	CurrentSettings *models.Settings
}

type NestPreparer interface {
	NestPrepare()
}

type NestFinisher interface {
	NestFinish()
}

func (c *BaseController) Prepare() {
	c.setParams()

	c.loadCurrentProfile()

	userID := c.GetSession("userinfo")
	if userID != nil {
		user := &models.User{Id: userID.(int64)}
		if err := user.Read("Id"); err == nil {
			c.IsLogin = true
			c.Userinfo = user
		} else {
			c.IsLogin = false
			c.DelSession("userinfo")
		}
	} else {
		c.IsLogin = false
	}

	c.Data["IsLogin"] = c.IsLogin
	c.Data["Userinfo"] = c.Userinfo

	if app, ok := c.AppController.(NestPreparer); ok {
		app.NestPrepare()
	}
}

func (c *BaseController) Finish() {
	if app, ok := c.AppController.(NestFinisher); ok {
		app.NestFinish()
	}
}

func (c *BaseController) GetLogin() *models.User {
	session := c.GetSession("userinfo")
	if session == nil {
		return nil
	}

	user := &models.User{Id: session.(int64)}
	_ = user.Read("Id")
	return user
}

func (c *BaseController) DelLogin() {
	c.DelSession("userinfo")
	c.IsLogin = false
	c.Userinfo = nil
}

func (c *BaseController) SetLogin(user *models.User) {
	c.SetSession("userinfo", user.Id)
	c.IsLogin = true
	c.Userinfo = user
}

func (c *BaseController) LoginPath() string {
	return c.URLFor("LoginController.Login")
}

func (c *BaseController) setParams() {
	params := make(map[string]string)
	c.Data["Params"] = params

	input, err := c.Input()
	if err != nil {
		return
	}

	for key, values := range input {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}
}

func (c *BaseController) loadCurrentProfile() {
	profile := c.GetString("profile")
	if profile == "" {
		if sessionProfile, ok := c.GetSession("profile").(string); ok {
			profile = sessionProfile
		}
	}
	if profile == "" {
		profile = state.DefaultProfile
	}

	settings, err := state.GetSettings(profile)
	if err != nil && profile != state.DefaultProfile {
		profile = state.DefaultProfile
		settings, _ = state.GetSettings(profile)
	}
	if settings == nil {
		settings = &models.Settings{Profile: profile}
	}

	c.CurrentProfile = profile
	c.CurrentSettings = settings
	c.SetSession("profile", profile)

	c.Data["CurrentProfile"] = profile
	if profiles, err := state.ListProfiles(); err == nil {
		c.Data["AvailableProfiles"] = profiles
	}
}

type BreadCrumbs struct {
	Title    string
	Subtitle string
}
