package models

import (
	"context"
	"database/sql"
	"path/filepath"
	"time"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/server/web"
)

const metricsAlias = "metrics"

// txOrmerAdapter adds a Begin method to orm.TxOrmer so it satisfies the orm.Ormer
// interface expected by existing helper functions.
type txOrmerAdapter struct {
	orm.TxOrmer
}

func (a txOrmerAdapter) Begin() (orm.TxOrmer, error) {
	return a.TxOrmer, nil
}

func (a txOrmerAdapter) BeginWithCtx(ctx context.Context) (orm.TxOrmer, error) {
	return a.TxOrmer, nil
}

func (a txOrmerAdapter) BeginWithOpts(opts *sql.TxOptions) (orm.TxOrmer, error) {
	return a.TxOrmer, nil
}

func (a txOrmerAdapter) BeginWithCtxAndOpts(ctx context.Context, opts *sql.TxOptions) (orm.TxOrmer, error) {
	return a.TxOrmer, nil
}

func (a txOrmerAdapter) DoTx(task func(ctx context.Context, txOrm orm.TxOrmer) error) error {
	return task(context.Background(), a.TxOrmer)
}

func (a txOrmerAdapter) DoTxWithCtx(ctx context.Context, task func(ctx context.Context, txOrm orm.TxOrmer) error) error {
	return task(ctx, a.TxOrmer)
}

func (a txOrmerAdapter) DoTxWithOpts(opts *sql.TxOptions, task func(ctx context.Context, txOrm orm.TxOrmer) error) error {
	return task(context.Background(), a.TxOrmer)
}

func (a txOrmerAdapter) DoTxWithCtxAndOpts(ctx context.Context, opts *sql.TxOptions, task func(ctx context.Context, txOrm orm.TxOrmer) error) error {
	return task(ctx, a.TxOrmer)
}

// MetricRecord contains a single metric sample that was gathered from the OpenVPN management interface.
type MetricRecord struct {
	Id          int64
	Category    string `orm:"size(32)"`
	Name        string `orm:"size(128)"`
	Value       float64
	Unit        string    `orm:"size(64)"`
	Description string    `orm:"size(256)"`
	RecordedAt  time.Time `orm:"auto_now_add;type(datetime)"`
}

// InitMetricsDB prepares a dedicated database for metric samples.
func InitMetricsDB() error {
	registerDriverOnce.Do(func() {
		if err := orm.RegisterDriver("sqlite3", orm.DRSqlite); err != nil {
			panic(err)
		}
	})

	dbPath := web.AppConfig.DefaultString("metricsDbPath", "./db/metrics.db")

	if err := ensureDir(filepath.Dir(dbPath)); err != nil {
		return err
	}

	// Note: for mattn/go-sqlite3 a plain path or "file:<path>" both work.
	dbSource := "file:" + dbPath

	if err := orm.RegisterDataBase(metricsAlias, "sqlite3", dbSource); err != nil {
		return err
	}

	orm.RegisterModel(
		new(MetricRecord),
		new(MetricSample),
		new(ClientSession),
		new(ClientEvent),
		new(RoutingCCD),
		new(DaemonInfo),
		new(UISnapshot),
	)

	// Create tables if not exist (no force, verbose logs on)
	if err := orm.RunSyncdb(metricsAlias, false, true); err != nil {
		return err
	}

	startMetricsRetention()
	return nil
}

// GetMetricsOrm returns an ormer bound to the metrics database alias.
func GetMetricsOrm() orm.Ormer {
	return orm.NewOrmUsingDB(metricsAlias)
}

// SaveMetrics persists metric samples into the dedicated metrics database.
func SaveMetrics(records []MetricRecord) error {
	if len(records) == 0 {
		return nil
	}

	// beego v2: no Ormer.Using(); use NewOrmUsingDB(alias)
	o := orm.NewOrmUsingDB(metricsAlias)

	for i := range records {
		if _, err := o.Insert(&records[i]); err != nil {
			return err
		}
	}
	return nil
}

// WithMetricsTx executes fn inside a transaction on metrics DB.
func WithMetricsTx(fn func(o orm.Ormer) error) error {
	o := orm.NewOrmUsingDB(metricsAlias)
	tx, err := o.Begin()
	if err != nil {
		return err
	}
	if err := fn(txOrmerAdapter{tx}); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func startMetricsRetention() {
	retentionDays := web.AppConfig.DefaultInt("MetricsRetentionDays", 90)
	intervalMinutes := web.AppConfig.DefaultInt("MetricsRetentionIntervalMinutes", 60)
	retention := time.Duration(retentionDays) * 24 * time.Hour
	interval := time.Duration(intervalMinutes) * time.Minute
	if retention <= 0 || interval <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-retention)
			o := orm.NewOrmUsingDB(metricsAlias)
			_, _ = o.Raw("DELETE FROM metric_sample WHERE recorded_at < ?", cutoff).Exec()
		}
	}()
}
