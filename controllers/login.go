package controllers

import (
	"context"
	"html/template"
	"log"
	"os"
	"strings"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	"github.com/nicesoft-labs/openvpn-ui/lib"
	"github.com/nicesoft-labs/openvpn-ui/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	oauth2api "google.golang.org/api/oauth2/v2"
)

var (
	oauthConf        *oauth2.Config
	oauthStateString = "random" // use a random string for security purposes
	allowedDomains   []string
)

func init() {
	oauthConf = buildOAuthConfig()
	allowedDomains = parseAllowedDomains(os.Getenv("ALLOWED_DOMAINS"))
}

type LoginController struct {
	BaseController
}

func (c *LoginController) Login() {
	if c.IsLogin {
		c.Ctx.Redirect(302, c.URLFor("MainController.Get"))
		return
	}

	c.TplName = "login.html"
	c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())
	if !c.Ctx.Input.IsPost() {
		return
	}

	flash := web.NewFlash()
	login := c.GetString("login")
	password := c.GetString("password")

	authType, err := web.AppConfig.String("AuthType")
	if err != nil {
		flash.Warning(err.Error())
		flash.Store(&c.Controller)
		return
	}

	user, err := lib.Authenticate(login, password, authType)
	if err != nil {
		flash.Warning(err.Error())
		flash.Store(&c.Controller)
		return
	}

	user.Lastlogintime = time.Now()
	if err = user.Update("Lastlogintime"); err != nil {
		flash.Warning(err.Error())
		flash.Store(&c.Controller)
		return
	}

	flash.Success("Successfully logged in")
	flash.Store(&c.Controller)

	c.SetLogin(user)

	c.Redirect(c.URLFor("MainController.Get"), 303)
}

func (c *LoginController) Logout() {
	c.DelLogin()
	flash := web.NewFlash()
	flash.Success("Successfully logged out")
	flash.Store(&c.Controller)

	c.Ctx.Redirect(302, c.URLFor("LoginController.Login"))
}

func (c *LoginController) GoogleLogin() {
	url := oauthConf.AuthCodeURL(oauthStateString)
	c.Redirect(url, 302)
}

func (c *LoginController) GoogleCallback() {
	state := c.GetString("state")
	if state != oauthStateString {
		c.Ctx.WriteString("Invalid OAuth state")
		return
	}

	code := c.GetString("code")
	token, err := oauthConf.Exchange(context.Background(), code)
	if err != nil {
		c.Ctx.WriteString("Code exchange failed: " + err.Error())
		return
	}

	client := oauthConf.Client(context.Background(), token)
	service, err := oauth2api.New(client)
	if err != nil {
		c.Ctx.WriteString("Failed to create OAuth2 service: " + err.Error())
		return
	}

	userinfo, err := service.Userinfo.Get().Do()
	if err != nil {
		c.Ctx.WriteString("Failed to get user info: " + err.Error())
		return
	}

	logs.Info("User Info: %+v", userinfo)

	if !isDomainAllowed(userinfo.Email) {
		c.Data["error"] = "Your Email is not allowed to login"
		c.TplName = "login.html"
		_ = c.Render()
		return
	}

	user, err := lib.GetUserByEmail(userinfo.Email)
	if err != nil {
		if err.Error() == "user not found" {
			user = &models.User{
				Email:         userinfo.Email,
				Name:          userinfo.Email,
				Login:         userinfo.Email,
				Lastlogintime: time.Now(),
				Allowed:       true,
			}
			if err = user.Insert(); err != nil {
				c.Ctx.WriteString("Failed to create new user: " + err.Error())
				return
			}
		} else {
			c.Ctx.WriteString("Error fetching user: " + err.Error())
			return
		}
	} else {
		user.Allowed = true
		user.Lastlogintime = time.Now()
		user.Name = userinfo.Email
		if err = user.Update("Allowed", "Lastlogintime", "Name"); err != nil {
			c.Ctx.WriteString("Failed to update user: " + err.Error())
			return
		}
	}

	if !user.Allowed {
		c.Data["error"] = "Access denied"
		c.TplName = "login.html"
		_ = c.Render()
		return
	}

	c.SetLogin(user)

	flash := web.NewFlash()
	flash.Success("Successfully logged in with Google")
	flash.Store(&c.Controller)

	c.Redirect(c.URLFor("MainController.Get"), 302)
}

func buildOAuthConfig() *oauth2.Config {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURL := os.Getenv("GOOGLE_REDIRECT_URL")

	if clientID == "" {
		log.Println("Environment variable GOOGLE_CLIENT_ID not set")
	}
	if clientSecret == "" {
		log.Println("Environment variable GOOGLE_CLIENT_SECRET not set")
	}
	if redirectURL == "" {
		log.Println("Environment variable GOOGLE_REDIRECT_URL not set")
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
}

func parseAllowedDomains(domains string) []string {
	if domains == "" {
		log.Println("Environment variable ALLOWED_DOMAINS not set")
		return []string{}
	}

	return strings.Split(domains, ",")
}

func isDomainAllowed(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	domain := parts[1]
	for _, allowed := range allowedDomains {
		if domain == allowed {
			return true
		}
	}

	return false
}
