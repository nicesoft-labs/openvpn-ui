package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/beego/beego/v2/server/web"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/routers"
	"github.com/d3vilh/openvpn-ui/state"
)

func main() {
	configDir := flag.String("config", "conf", "Path to config dir")
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

	routers.Init(*configDir)

	lib.AddFuncMaps()
	web.Run()
}

const defaultAppConfig = `; we use this when building the app.
appname = openvpn-ui
httpport = 8080
runmode = prod
EnableGzip = true
EnableAdmin = false
sessionon = true
CopyRequestBody = true
AuthType = "password"
DbPath = "./db/data.db"
MetricsDbPath = "./db/metrics.db"
EasyRsaPath = "/usr/share/easy-rsa"
OpenVpnPath = "/etc/openvpn"
OpenVpnManagementAddress = "openvpn:2080"
OpenVpnManagementNetwork = "tcp"
OVConfigLogVerbose = "1"

# google config
googleClientID = your-google-clientid
googleClientSecret = your-google-secret
googleRedirectURL = http://localhost:8080/auth/google/callback
`

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
