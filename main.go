package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/metrics"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/routers"
	"github.com/d3vilh/openvpn-ui/state"
	mi "github.com/nicesoft-labs/openvpn-server-config/server/mi"
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

	debugMode := web.BConfig.RunMode == web.DEV

	models.InitDB()
	models.CreateDefaultUsers()
	defaultSettings, err := models.CreateDefaultSettings()
	if err != nil {
		panic(err)
	}

	models.CreateDefaultOVConfig(*configDir, defaultSettings.OVConfigPath, defaultSettings.MIAddress, defaultSettings.MINetwork)
	models.CreateDefaultOVClientConfig(*configDir, defaultSettings.OVConfigPath, defaultSettings.MIAddress, defaultSettings.MINetwork)
	models.CreateDefaultEasyRSAConfig(*configDir, defaultSettings.EasyRSAPath, defaultSettings.MIAddress, defaultSettings.MINetwork)
	state.GlobalCfg = *defaultSettings

	metricsCfg := metrics.LoadConfig()
	if debugMode {
		logs.Debug(
			"metrics: dev mode enabled; config enabled=%t db_path=%s poll_interval=%s mi=%s://%s",
			metricsCfg.Enabled, metricsCfg.DBPath, metricsCfg.PollInterval, metricsCfg.MINetwork, metricsCfg.MIAddress,
		)
	}
	var metricsHandlerFunc func(http.ResponseWriter, *http.Request)
	if metricsCfg.Enabled {
		if err := os.MkdirAll(filepath.Dir(metricsCfg.DBPath), 0o755); err != nil {
			logs.Warn("metrics: create db dir: %v", err)
		}
		logger := logs.GetBeeLogger()
		sqliteStore, err := metrics.NewSQLiteStore(metricsCfg.DBPath, logger, debugMode)
		if err != nil {
			logs.Warn("metrics: init store: %v", err)
		} else {
			if err := sqliteStore.InitSchema(context.Background()); err != nil {
				logs.Warn("metrics: init schema: %v", err)
			} else {
				metrics.SetGlobalStore(sqliteStore)
				metricsHandler := metrics.NewHandler(metricsCfg, sqliteStore, logger)
				metricsHandlerFunc = metricsHandler.HandleClientEvent
				miClient := mi.NewClient(metricsCfg.MINetwork, metricsCfg.MIAddress)
				collector := metrics.NewCollector(metricsCfg, sqliteStore, miClient, logger)
				go collector.Run(context.Background())
			}
		}
	}

	routers.Init(*configDir, metricsHandlerFunc)

	lib.AddFuncMaps()
	web.Run()
}

const defaultAppConfig = `; we use this when building the app.
appname = nicevpn-ui
httpport = 8080
runmode = prod
EnableGzip = true
EnableAdmin = false
sessionon = true
CopyRequestBody = true
AuthType = "password"
DbPath = "/etc/nicevpn/db/data.db"
EasyRsaPath = "/usr/share/easy-rsa"
OpenVpnPath = "/etc/openvpn"
OpenVpnManagementAddress = "127.0.0.1:2080"
OpenVpnManagementNetwork = "tcp"
OVConfigLogVerbose = "1"

# metrics
metrics.enabled = false
metrics.db_path = /var/lib/nicevpn/metrics.db
metrics.poll_interval = 30s
metrics.mi_network = tcp
metrics.mi_address = 127.0.0.1:2080

# yandex config
yandexClientID = your-yandex-clientid
yandexClientSecret = your-yandex-secret
yandexRedirectURL = http://localhost:8080/auth/yandex/callback
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
