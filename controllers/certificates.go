package controllers

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"text/template"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/core/validation"
	"github.com/beego/beego/v2/server/web"
	clientconfig "github.com/d3vilh/openvpn-server-config/client/client-config"
	"github.com/nicesoft-labs/openvpn-ui/lib"
	"github.com/nicesoft-labs/openvpn-ui/models"
)

type NewCertParams struct {
	Name       string `form:"Name" valid:"Required;"`
	Staticip   string `form:"staticip"`
	Passphrase string `form:"passphrase"`
	ExpireDays string `form:"EasyRSACertExpire"`
	Email      string `form:"EasyRSAReqEmail"`
	Country    string `form:"EasyRSAReqCountry"`
	Province   string `form:"EasyRSAReqProvince"`
	City       string `form:"EasyRSAReqCity"`
	Org        string `form:"EasyRSAReqOrg"`
	OrgUnit    string `form:"EasyRSAReqOu"`
	TFAName    string `form:"TFAName"`
	TFAIssuer  string `form:"TFAIssuer"`
}

type CertificatesController struct {
	BaseController
	ConfigDir string
}

func (c *CertificatesController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}
	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: "Certificates",
	}
}

// @router /certificates/:key [get]
func (c *CertificatesController) Download() {
	name := c.GetString(":key")
	filename := fmt.Sprintf("%s.ovpn", name)

	c.Ctx.Output.Header("Content-Type", "application/octet-stream")
	c.Ctx.Output.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))

	keysPath := filepath.Join(c.CurrentSettings.OVConfigPath, "pki/issued")

	cfgPath, err := c.saveClientConfig(keysPath, name)
	if err != nil {
		logs.Error(err)
		return
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		logs.Error(err)
		return
	}

	if _, err = c.Controller.Ctx.ResponseWriter.Write(data); err != nil {
		logs.Error(err)
	}
}

// @router /certificates [get]
func (c *CertificatesController) Get() {
	c.TplName = "certificates.html"
	c.populateCertView()
	c.Data["EasyRSA"] = c.loadEasyRSAConfig()
	c.Data["SettingsC"] = c.loadClientConfig()
}

func (c *CertificatesController) DisplayImage() {
	imageName := c.Ctx.Input.Param(":imageName")
	imagePath := filepath.Join(c.CurrentSettings.OVConfigPath, "clients", imageName+".png")

	data, err := os.ReadFile(imagePath)
	if err != nil {
		c.Ctx.Output.SetStatus(404)
		c.Ctx.WriteString("Image not found")
		logs.Error("Error reading image file: %v", err)
		return
	}

	c.Ctx.Output.Header("Content-Type", "image/png")
	c.Ctx.Output.Body(data)
}

func (c *CertificatesController) populateCertView() {
	path := filepath.Join(c.CurrentSettings.OVConfigPath, "pki/index.txt")
	certs, err := lib.ReadCerts(path)
	if err != nil {
		logs.Error(err)
	}
	lib.Dump(certs)
	c.Data["certificates"] = &certs
	c.Data["EasyRSA"] = c.loadEasyRSAConfig()
	c.Data["SettingsC"] = c.loadClientConfig()
}

// @router /certificates [post]
func (c *CertificatesController) Post() {
	c.TplName = "certificates.html"
	flash := web.NewFlash()

	cParams := NewCertParams{}
	if err := c.ParseForm(&cParams); err != nil {
		logs.Error(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
		c.populateCertView()
		return
	}

	if vMap := validateCertParams(cParams); vMap != nil {
		c.Data["validation"] = vMap
		c.populateCertView()
		return
	}

	logs.Info(
		"Controller: Creating certificate with parameters: Name=%s, Staticip=%s, Passphrase=%s, ExpireDays=%s, Email=%s, Country=%s, Province=%s, City=%s, Org=%s, OrgUnit=%s, TFAName=%s, TFAIssuer=%s",
		cParams.Name,
		cParams.Staticip,
		cParams.Passphrase,
		cParams.ExpireDays,
		cParams.Email,
		cParams.Country,
		cParams.Province,
		strconv.Quote(cParams.City),
		strconv.Quote(cParams.Org),
		strconv.Quote(cParams.OrgUnit),
		cParams.TFAName,
		cParams.TFAIssuer,
	)

	if err := lib.CreateCertificate(
		c.CurrentSettings.OVConfigPath,
		cParams.Name,
		cParams.Staticip,
		cParams.Passphrase,
		cParams.ExpireDays,
		cParams.Email,
		cParams.Country,
		cParams.Province,
		strconv.Quote(cParams.City),
		strconv.Quote(cParams.Org),
		strconv.Quote(cParams.OrgUnit),
		cParams.TFAName,
		cParams.TFAIssuer,
	); err != nil {
		logs.Error(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
		c.populateCertView()
		return
	}

	flash.Success("Success! Certificate for the name \"" + cParams.Name + "\" has been created")
	flash.Store(&c.Controller)
	c.populateCertView()
}

// @router /certificates/revoke/:key [get]
func (c *CertificatesController) Revoke() {
	c.TplName = "certificates.html"
	flash := web.NewFlash()
	name := c.GetString(":key")
	serial := c.GetString(":serial")
	tfaname := c.GetString(":tfaname")

	if err := lib.RevokeCertificate(c.CurrentSettings.OVConfigPath, name, serial, tfaname); err != nil {
		logs.Error(err)
	} else {
		flash.Success("Success! Certificate for the name \"" + name + "\" and serial  \"" + serial + "\" has been revoked")
		flash.Store(&c.Controller)
	}
	c.populateCertView()
}

// @router /certificates/restart [get]
func (c *CertificatesController) Restart() {
	lib.Restart(c.CurrentSettings.OVConfigPath)
	c.Redirect(c.URLFor("CertificatesController.Get"), 302)
}

// @router /certificates/burn/:key/:serial/:tfaname [get]
func (c *CertificatesController) Burn() {
	c.TplName = "certificates.html"
	flash := web.NewFlash()
	CN := c.GetString(":key")
	serial := c.GetString(":serial")
	tfaname := c.GetString(":tfaname")
	logs.Info("Controller: Burning certificate with parameters: CN=%s, serial=%s, tfaname=%s", CN, serial, tfaname)

	if err := lib.BurnCertificate(c.CurrentSettings.OVConfigPath, CN, serial, tfaname); err != nil {
		logs.Error(err)
	} else {
		flash.Success("Success! Certificate for the name \"" + CN + "\" and serial  \"" + serial + "\"  has been removed")
		flash.Store(&c.Controller)
	}
	c.populateCertView()
}

// @router /certificates/revoke/:key [get]
func (c *CertificatesController) Renew() {
	c.TplName = "certificates.html"
	flash := web.NewFlash()
	name := c.GetString(":key")
	localip := c.GetString(":localip")
	serial := c.GetString(":serial")
	tfaname := c.GetString(":tfaname")

	if err := lib.RenewCertificate(c.CurrentSettings.OVConfigPath, name, localip, serial, tfaname); err != nil {
		logs.Error(err)
	} else {
		flash.Success("Success! Certificate for the name \"" + name + "\"  and IP \"" + localip + "\" and Serial \"" + serial + "\" has been renewed")
		flash.Store(&c.Controller)
	}
	c.populateCertView()
}

func validateCertParams(cert NewCertParams) map[string]map[string]string {
	valid := validation.Validation{}
	b, err := valid.Valid(&cert)
	if err != nil {
		logs.Error(err)
		return nil
	}
	if !b {
		return lib.CreateValidationMap(valid)
	}
	return nil
}

func (c *CertificatesController) saveClientConfig(keysPath string, name string) (string, error) {
	cfg := clientconfig.New()
	keysPathCa := filepath.Join(c.CurrentSettings.OVConfigPath, "pki")

	ovClientConfig := &models.OVClientConfig{Profile: c.CurrentProfile}
	if err := ovClientConfig.Read("Profile"); err != nil {
		return "", err
	}

	cfg.ServerAddress = ovClientConfig.ServerAddress
	cfg.OpenVpnServerPort = ovClientConfig.OpenVpnServerPort
	cfg.AuthUserPass = ovClientConfig.AuthUserPass
	cfg.ResolveRetry = ovClientConfig.ResolveRetry
	cfg.OVClientUser = ovClientConfig.OVClientUser
	cfg.OVClientGroup = ovClientConfig.OVClientGroup
	cfg.PersistTun = ovClientConfig.PersistTun
	cfg.PersistKey = ovClientConfig.PersistKey
	cfg.RemoteCertTLS = ovClientConfig.RemoteCertTLS
	cfg.RedirectGateway = ovClientConfig.RedirectGateway
	cfg.Proto = ovClientConfig.Proto
	cfg.Auth = ovClientConfig.Auth
	cfg.Cipher = ovClientConfig.Cipher
	cfg.Device = ovClientConfig.Device
	cfg.AuthNoCache = ovClientConfig.AuthNoCache
	cfg.TlsClient = ovClientConfig.TlsClient
	cfg.Verbose = ovClientConfig.Verbose
	cfg.CustomConfOne = ovClientConfig.CustomConfOne
	cfg.CustomConfTwo = ovClientConfig.CustomConfTwo
	cfg.CustomConfThree = ovClientConfig.CustomConfThree

	ca, err := os.ReadFile(filepath.Join(keysPathCa, "ca.crt"))
	if err != nil {
		return "", err
	}
	cfg.Ca = string(ca)

	ta, err := os.ReadFile(filepath.Join(keysPathCa, "ta.key"))
	if err != nil {
		return "", err
	}
	cfg.Ta = string(ta)

	cert, err := os.ReadFile(filepath.Join(keysPath, name+".crt"))
	if err != nil {
		return "", err
	}
	cfg.Cert = string(cert)

	keysPathKey := filepath.Join(c.CurrentSettings.OVConfigPath, "pki/private")
	key, err := os.ReadFile(filepath.Join(keysPathKey, name+".key"))
	if err != nil {
		return "", err
	}
	cfg.Key = string(key)

	serverConfig := models.OVConfig{Profile: c.CurrentProfile}
	_ = serverConfig.Read("Profile")
	cfg.Port = serverConfig.Port

	destPath := filepath.Join(c.CurrentSettings.OVConfigPath, "clients", name+".ovpn")
	if err := SaveToFile(filepath.Join(c.ConfigDir, "openvpn-client-config.tpl"), cfg, destPath); err != nil {
		logs.Error(err)
		return "", err
	}

	return destPath, nil
}

func GetText(tpl string, c clientconfig.Config) (string, error) {
	t := template.New("config")
	t, err := t.Parse(tpl)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	if err = t.Execute(buf, c); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func SaveToFile(tplPath string, c clientconfig.Config, destPath string) error {
	tpl, err := os.ReadFile(tplPath)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}

	str, err := GetText(string(tpl), c)
	if err != nil {
		return err
	}

	return os.WriteFile(destPath, []byte(str), 0644)
}

func (c *CertificatesController) loadEasyRSAConfig() *models.EasyRSAConfig {
	cfg := models.EasyRSAConfig{Profile: c.CurrentProfile}
	_ = cfg.Read("Profile")
	return &cfg
}

func (c *CertificatesController) loadClientConfig() *models.OVClientConfig {
	cfg := models.OVClientConfig{Profile: c.CurrentProfile}
	_ = cfg.Read("Profile")
	return &cfg
}
