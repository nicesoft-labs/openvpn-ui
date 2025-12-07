package metrics

import (
	"time"

	"github.com/beego/beego/v2/server/web"
)

// MetricsConfig describes configuration for the metrics subsystem.
type MetricsConfig struct {
	Enabled      bool          `yaml:"enabled"`
	DBPath       string        `yaml:"db_path"`
	PollInterval time.Duration `yaml:"poll_interval"`
	MINetwork    string        `yaml:"mi_network"`
	MIAddress    string        `yaml:"mi_address"`
}

const (
	defaultDBPath       = "/var/lib/nicevpn/metrics.db"
	defaultPollInterval = 30 * time.Second
)

// LoadConfig reads metrics configuration from Beego app config.
func LoadConfig() MetricsConfig {
	cfg := MetricsConfig{
		Enabled:      false,
		DBPath:       defaultDBPath,
		PollInterval: defaultPollInterval,
		MINetwork:    "tcp",
		MIAddress:    "127.0.0.1:2080",
	}

	if v, err := web.AppConfig.Bool("metrics.enabled"); err == nil {
		cfg.Enabled = v
	}
	if v := web.AppConfig.DefaultString("metrics.db_path", cfg.DBPath); v != "" {
		cfg.DBPath = v
	}
	if v := web.AppConfig.DefaultString("metrics.mi_network", cfg.MINetwork); v != "" {
		cfg.MINetwork = v
	}
	if v := web.AppConfig.DefaultString("metrics.mi_address", cfg.MIAddress); v != "" {
		cfg.MIAddress = v
	}
	if v := web.AppConfig.DefaultString("metrics.poll_interval", ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.PollInterval = d
		}
	}

	return cfg
}
