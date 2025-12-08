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

	// Log enrichment options
	LogEnrichmentEnabled bool   `yaml:"log_enrichment_enabled"`
	OpenVPNLogPath       string `yaml:"openvpn_log_path"`
}

const (
	defaultDBPath       = "/var/lib/nicevpn/metrics.db"
	defaultPollInterval = 30 * time.Second
	defaultLogPath      = "/var/log/openvpn/openvpn.log"
)

// LoadConfig reads metrics configuration from Beego app config.
func LoadConfig() MetricsConfig {
	cfg := MetricsConfig{
		Enabled:              false,
		DBPath:               defaultDBPath,
		PollInterval:         defaultPollInterval,
		MINetwork:            "tcp",
		MIAddress:            "127.0.0.1:2080",
		LogEnrichmentEnabled: true,
		OpenVPNLogPath:       defaultLogPath,
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
	if v, err := web.AppConfig.Bool("metrics.log_enrichment_enabled"); err == nil {
		cfg.LogEnrichmentEnabled = v
	}
	if v := web.AppConfig.DefaultString("metrics.openvpn_log_path", cfg.OpenVPNLogPath); v != "" {
		cfg.OpenVPNLogPath = v
	}
	if v := web.AppConfig.DefaultString("metrics.poll_interval", ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.PollInterval = d
		}
	}

	return cfg
}
