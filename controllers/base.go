package controllers

import (
	"strconv"

	"github.com/beego/beego/v2/server/web"
	"github.com/d3vilh/openvpn-ui/models"
)

type BaseController struct {
	web.Controller

	Userinfo *models.User
	IsLogin  bool
}

type NestPreparer interface {
	NestPrepare()
}

type NestFinisher interface {
	NestFinish()
}

// sessionUserID безопасно извлекает идентификатор пользователя из сессии.
// Поддерживает int64, int и string.
func (c *BaseController) sessionUserID() (int64, bool) {
	v := c.GetSession("userinfo")
	switch id := v.(type) {
	case int64:
		return id, true
	case int:
		return int64(id), true
	case string:
		n, err := strconv.ParseInt(id, 10, 64)
		if err == nil {
			return n, true
		}
	}
	return 0, false
}

func (c *BaseController) Prepare() {
	c.SetParams()

	if uid, ok := c.sessionUserID(); ok {
		user := models.User{Id: uid}
		if err := user.Read("Id"); err == nil {
			c.IsLogin = true
			c.Userinfo = &user
		} else {
			// Пользователь не найден — чистим сессию
			c.IsLogin = false
			c.DelSession("userinfo")
			c.Userinfo = nil
		}
	} else {
		c.IsLogin = false
		c.Userinfo = nil
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

// GetLogin возвращает пользователя из сессии или nil, если не залогинен.
func (c *BaseController) GetLogin() *models.User {
	if uid, ok := c.sessionUserID(); ok {
		u := &models.User{Id: uid}
		_ = u.Read("Id")
		return u
	}
	return nil
}

func (c *BaseController) DelLogin() {
	c.DelSession("userinfo")
	c.IsLogin = false
	c.Userinfo = nil
}

func (c *BaseController) SetLogin(user *models.User) {
	// Храним ID в сессии как int64 — единообразно
	c.SetSession("userinfo", int64(user.Id))
	c.IsLogin = true
	c.Userinfo = user
}

func (c *BaseController) LoginPath() string {
	return c.URLFor("LoginController.Login")
}

func (c *BaseController) SetParams() {
	c.Data["Params"] = make(map[string]string)
	input, err := c.Input() // в вашей версии: (url.Values, error)
	if err != nil {
		// можно залогировать, если нужно
		return
	}
	for k, v := range input {
		if len(v) > 0 {
			c.Data["Params"].(map[string]string)[k] = v[0]
		}
	}
}

type BreadCrumbs struct {
	Title    string
	Subtitle string
}
