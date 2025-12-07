package metrics

import (
	"context"
	"time"

	"github.com/beego/beego/v2/core/logs"
	mi "github.com/nicesoft-labs/openvpn-server-config/server/mi"
)

// Collector polls OpenVPN management interface and updates metrics store.
type Collector struct {
	cfg   MetricsConfig
	store Store
	mi    *mi.Client
	log   *logs.BeeLogger
}

// NewCollector creates a new Collector instance.
func NewCollector(cfg MetricsConfig, store Store, miClient *mi.Client, log *logs.BeeLogger) *Collector {
	return &Collector{cfg: cfg, store: store, mi: miClient, log: log}
}

// Run starts periodic polling until context cancellation.
func (c *Collector) Run(ctx context.Context) {
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

	stats, _ := c.mi.GetLoadStats()
	if err := c.store.UpdateSessionsFromStatus(ctx, status); err != nil {
		c.log.Warn("metrics: UpdateSessionsFromStatus: %v", err)
	}
	if err := c.store.InsertMgmtSnapshot(ctx, time.Now().UTC(), status, stats); err != nil {
		c.log.Warn("metrics: InsertMgmtSnapshot: %v", err)
	}
}
