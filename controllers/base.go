package controllers

import (
	"reflect"
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

// безопасно извлекаем userID из сессии; поддерживаем int64/int/string
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

	// Защита от typed-nil в AppController перед вызовом NestPrepare
	ac := c.AppController
	if ac != nil {
		rv := reflect.ValueOf(ac)
		// если это указатель и он nil — не вызываем методы
		if !(rv.Kind() == reflect.Ptr && rv.IsNil()) {
			if app, ok := ac.(NestPreparer); ok {
				app.NestPrepare()
			}
		}
	}
}

func (c *BaseController) Finish() {
	// Та же защита перед NestFinish
	ac := c.AppController
	if ac != nil {
		rv := reflect.ValueOf(ac)
		if !(rv.Kind() == reflect.Ptr && rv.IsNil()) {
			if app, ok := ac.(NestFinisher); ok {
				app.NestFinish()
			}
		}
	}
}

// Возвращает пользователя из сессии или nil
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
	// Храним ID в сессии единообразно как int64
	c.SetSession("userinfo", int64(user.Id))
	c.IsLogin = true
	c.Userinfo = user
}

func (c *BaseController) LoginPath() string {
	return c.URLFor("LoginController.Login")
}

func (c *BaseController) SetParams() {
	params := make(map[string]string)
	input, err := c.Input() // (url.Values, error) в beego v2
	if err == nil {
		for k, v := range input {
			if len(v) > 0 {
				params[k] = v[0]
			}
		}
	}
	c.Data["Params"] = params
}

type BreadCrumbs struct {
	Title    string
	Subtitle string
}
