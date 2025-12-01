package models

import (
	"github.com/beego/beego/v2/client/orm"
	"time"
)

// UISnapshot stores a serialized payload for UI endpoints.
type UISnapshot struct {
	Id        int64     `orm:"pk;auto"`
	Payload   string    `orm:"type(longtext)"`
	UpdatedAt time.Time `orm:"type(datetime)"`
}

// SaveUISnapshot upserts the snapshot payload (Id=1) into the metrics database.
func SaveUISnapshot(payload string, updatedAt time.Time) error {
	o := orm.NewOrmUsingDB(metricsAlias)
	snap := UISnapshot{Id: 1}
	if err := o.Read(&snap); err == nil {
		snap.Payload = payload
		snap.UpdatedAt = updatedAt.UTC()
		_, err = o.Update(&snap, "Payload", "UpdatedAt")
		return err
	} else if err == orm.ErrNoRows {
		snap.Payload = payload
		snap.UpdatedAt = updatedAt.UTC()
		_, err = o.Insert(&snap)
		return err
	} else {
		return err
	}
}

// GetUISnapshot returns the stored payload and its timestamp.
func GetUISnapshot() (string, time.Time, error) {
	o := orm.NewOrmUsingDB(metricsAlias)
	snap := UISnapshot{Id: 1}
	if err := o.Read(&snap); err != nil {
		return "", time.Time{}, err
	}
	return snap.Payload, snap.UpdatedAt.UTC(), nil
}
