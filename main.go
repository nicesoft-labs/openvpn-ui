package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/routers"
	"github.com/d3vilh/openvpn-ui/services/statuscollector"
	"github.com/d3vilh/openvpn-ui/state"
)

func main() {
	configDir := flag.String("config", "/etc/nicevpn", "Path to config dir")
	flag.Parse()

	configFile := filepath.Join(*configDir, "app.conf")

	if err := ensureConfigFile(*configDir, configFile); err != nil {
		panic(err)
	}
	fmt.Println("Config file:", configFile)

	if err := web.LoadAppConfig("ini", configFile); err != nil {
		panic(err)
	}

	models.InitDB()
	if err := models.InitMetricsDB(); err != nil {
		panic(err)
	}
	models.CreateDefaultUsers()
	defaultSettings, err := models.CreateDefaultSettings()
	if err != nil {
		panic(err)
	}

	models.CreateDefaultOVConfig(*configDir, defaultSettings.OVConfigPath, defaultSettings.MIAddress, defaultSettings.MINetwork)
	models.CreateDefaultOVClientConfig(*configDir, defaultSettings.OVConfigPath, defaultSettings.MIAddress, defaultSettings.MINetwork)
	models.CreateDefaultEasyRSAConfig(*configDir, defaultSettings.EasyRSAPath, defaultSettings.MIAddress, defaultSettings.MINetwork)
	state.GlobalCfg = *defaultSettings

	collector := lib.NewObservabilityCollector()
	collector.Start()

	statuscollector.Start(loadStatusCollectorConfig())

	if err := lib.GenerateUIDataReport("ui-data-report.md"); err != nil {
		fmt.Println("report generation error:", err)
	}

	routers.Init(*configDir)

	lib.AddFuncMaps()
	web.Run()
}

const defaultAppConfig = `AppName = openvpn-ui
HttpPort = 8080
RunMode = dev
EnableGzip = true
EnableAdmin = true
SessionOn = true
CopyRequestBody = true
DbPath = "/srv/nicevpn/db/data.db"
MetricsDbPath = "/srv/nicevpn/db/metrics.db"
AuthType = "password"
; LdapAddress = "localhost:389"
; LdapDn = "cn=%s,ou=users,dc=syncloud,dc=org"
; plain/tls/starttls
; LdapTransport = "plain"
; LdapInsecureSkipVerify = true
;EasyRsaPath = "/usr/share/easy-rsa"
EasyRsaPath = "/srv/nicevpn/easy-rsa"
OpenVpnPath = "/srv/nicevpn/openvpn"
OpenVpnManagementAddress = "127.0.0.1:2080"
OpenVpnManagementNetwork = "tcp"
OpenVpnManagementPollInterval = "5s"
OpenVpnManagementDialTimeout = "2s"
OpenVpnManagementRWTimeout = "2s"
OpenVpnStatusFilePath = "/var/log/status.log"
OpenVpnStatusFilePollInterval = "2s"
OpenVpnStatusFileSessionHardTimeout = "1s"
OpenVpnStatusFileBackoffMax = "10s"`

func ensureConfigFile(configDir, configFile string) error {
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if _, err := os.Stat(configFile); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat config file: %w", err)
	}

	return os.WriteFile(configFile, []byte(defaultAppConfig), 0o644)
}

func loadStatusCollectorConfig() statuscollector.Config {
	return statuscollector.Config{
		StatusFilePath:     web.AppConfig.DefaultString("OpenVpnStatusFilePath", "/var/log/status.log"),
		PollInterval:       parseDurationConfig("OpenVpnStatusFilePollInterval", 2*time.Second),
		SessionHardTimeout: parseDurationConfig("OpenVpnStatusFileSessionHardTimeout", 1*time.Second),
		BackoffMax:         parseDurationConfig("OpenVpnStatusFileBackoffMax", 10*time.Second),
	}
}

func parseDurationConfig(key string, def time.Duration) time.Duration {
	raw := web.AppConfig.DefaultString(key, def.String())
	if raw == "" {
		return def
	}
	val, err := time.ParseDuration(raw)
	if err != nil {
		fmt.Printf("invalid %s: %v, using default %s\n", key, err, def)
		return def
	}
	return val
}
