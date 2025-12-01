package models

import (
	"path/filepath"
	"time"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/server/web"
)

const metricsAlias = "metrics"

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
	)

	// Create tables if not exist (no force, verbose logs on)
	if err := orm.RunSyncdb(metricsAlias, false, true); err != nil {
		return err
	}

	return nil
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
