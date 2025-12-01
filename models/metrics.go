package models

import (
	"path/filepath"
	"time"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/server/web"
)

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

	dbSource := "file:" + dbPath
	if err := orm.RegisterDataBase("metrics", "sqlite3", dbSource); err != nil {
		return err
	}

	orm.RegisterModel(new(MetricRecord))

	if err := orm.RunSyncdb("metrics", false, true); err != nil {
		return err
	}

	return nil
}

// SaveMetrics persists metric samples into the dedicated metrics database.
func SaveMetrics(records []MetricRecord) error {
	if len(records) == 0 {
		return nil
	}

	o := orm.NewOrm()
	if err := o.Using("metrics"); err != nil {
		return err
	}

	for i := range records {
		if _, err := o.Insert(&records[i]); err != nil {
			return err
		}
	}

	return nil
}
