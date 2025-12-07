package metrics

import (
	"context"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	mi "github.com/nicesoft-labs/openvpn-server-config/server/mi"
)

// Collector polls OpenVPN management interface and updates metrics store.
type Collector struct {
	cfg   MetricsConfig
	store Store
	mi    *mi.Client
	log   *logs.BeeLogger
	debug bool
}

// NewCollector creates a new Collector instance.
func NewCollector(cfg MetricsConfig, store Store, miClient *mi.Client, log *logs.BeeLogger) *Collector {
	return &Collector{cfg: cfg, store: store, mi: miClient, log: log, debug: web.BConfig.RunMode == web.DEV}
}

// Run starts periodic polling until context cancellation.
func (c *Collector) Run(ctx context.Context) {
	if c.debug {
		c.log.Debug(
			"metrics: collector starting in dev mode poll_interval=%s mi_network=%s mi_address=%s",
			c.cfg.PollInterval, c.cfg.MINetwork, c.cfg.MIAddress,
		)
	}
	ticker := time.NewTicker(c.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.pollOnce(ctx)
		}
	}
}

func (c *Collector) pollOnce(ctx context.Context) {
	status, err := c.mi.GetStatus()
	if err != nil {
		c.log.Warn("metrics: GetStatus failed: %v", err)
		return
	}
	if c.debug {
		c.log.Debug(
			"metrics: fetched status title=%s time=%s clients=%d routes=%d",
			status.Title, status.Time, len(status.ClientList), len(status.RoutingTable),
		)
		for _, client := range status.ClientList {
			if client == nil {
				continue
			}
			c.log.Debug(
				"metrics: client=%s user=%s real=%s vpn_ip=%s bytes_in=%d bytes_out=%d connected=%s",
				client.CommonName, client.Username, client.RealAddress, client.VirtualAddress, client.BytesReceived, client.BytesSent, client.ConnectedSince,
			)
		}
	}

	stats, _ := c.mi.GetLoadStats()
	if c.debug && stats != nil {
		c.log.Debug(
			"metrics: load stats n_clients=%d bytes_in=%d bytes_out=%d",
			stats.NClients, stats.BytesIn, stats.BytesOut,
		)
	}
	if err := c.store.UpdateSessionsFromStatus(ctx, status); err != nil {
		c.log.Warn("metrics: UpdateSessionsFromStatus: %v", err)
	}
	if err := c.store.InsertMgmtSnapshot(ctx, time.Now().UTC(), status, stats); err != nil {
		c.log.Warn("metrics: InsertMgmtSnapshot: %v", err)
	}
}
