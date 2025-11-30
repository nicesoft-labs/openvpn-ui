package main

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/beego/beego/v2/server/web"
	"github.com/nicesoft-labs/openvpn-ui/lib"
	"github.com/nicesoft-labs/openvpn-ui/models"
	"github.com/nicesoft-labs/openvpn-ui/routers"
	"github.com/nicesoft-labs/openvpn-ui/state"
)

func main() {
	configDir := flag.String("config", "conf", "Path to config dir")
	flag.Parse()

	configFile := filepath.Join(*configDir, "app.conf")
	fmt.Println("Config file:", configFile)

	if err := web.LoadAppConfig("ini", configFile); err != nil {
		panic(err)
	}

	models.InitDB()
	models.CreateDefaultUsers()
	defaultSettings, err := models.CreateDefaultSettings()
	if err != nil {
		panic(err)
	}

	models.CreateDefaultOVConfig(*configDir, defaultSettings.OVConfigPath, defaultSettings.MIAddress, defaultSettings.MINetwork, defaultSettings.Profile)
	models.CreateDefaultOVClientConfig(*configDir, defaultSettings.OVConfigPath, defaultSettings.MIAddress, defaultSettings.MINetwork, defaultSettings.Profile)
	models.CreateDefaultEasyRSAConfig(*configDir, defaultSettings.EasyRSAPath, defaultSettings.MIAddress, defaultSettings.MINetwork, defaultSettings.Profile)
	state.GlobalCfg = *defaultSettings

	routers.Init(*configDir)

	lib.AddFuncMaps()
	web.Run()
}
