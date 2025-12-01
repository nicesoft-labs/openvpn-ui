package models

import (
	"encoding/json"
	"time"

	"github.com/beego/beego/v2/client/orm"
)

// MetricSample stores raw metric points collected from OpenVPN management
// interface or OS probes. LabelsJSON keeps dynamic labels like common_name,
// real_addr, virt_addr, peer_id, tls params, etc.
type MetricSample struct {
	Id         int64
	Name       string `orm:"size(128);index"`
	Value      float64
	Unit       string    `orm:"size(64);null"`
	LabelsJSON string    `orm:"type(text);null"`
	RecordedAt time.Time `orm:"auto_now_add;type(datetime);index"`
	Source     string    `orm:"size(32);index"`
	MetricType string    `orm:"size(16);null"`
}

// ClientSession represents the current state of a connected client and is
// refreshed via status/bytecount polling. LookupKey is a deterministic unique
// identifier used for upserts (client_id if present, otherwise composite).
type ClientSession struct {
	Id             int64
	LookupKey      string    `orm:"size(256);unique"`
	ClientID       string    `orm:"size(64);null"`
	PeerID         string    `orm:"size(64);null"`
	CommonName     string    `orm:"size(128);index"`
	RealAddr       string    `orm:"size(128);null"`
	VirtAddr       string    `orm:"size(128);null"`
	VirtAddr6      string    `orm:"size(128);null"`
	Username       string    `orm:"size(128);null"`
	ConnectedSince time.Time `orm:"null;type(datetime);index"`
	LastRef        time.Time `orm:"null;type(datetime);index"`
	BytesRxTotal   uint64    `orm:"default(0)"`
	BytesTxTotal   uint64    `orm:"default(0)"`
	TLSVersion     string    `orm:"size(64);null"`
	DataCipher     string    `orm:"size(128);null"`
	AuthAlgo       string    `orm:"size(128);null"`
	Platform       string    `orm:"size(128);null"`
	GUIVersion     string    `orm:"size(128);null"`
	OVPNVersion    string    `orm:"size(128);null"`
	Proto          string    `orm:"size(64);null"`
	PushMode       string    `orm:"size(32);null"`
	RoutesJSON     string    `orm:"type(text);null"`
	UpdatedAt      time.Time `orm:"auto_now;type(datetime);index"`
}

// ClientEvent captures CONNECTED/RECONNECTING/EXITING/TLS_ERROR/AUTH_FAILED
// and other event lines from state/log streams.
type ClientEvent struct {
	Id         int64
	Ts         time.Time `orm:"auto_now_add;type(datetime);index"`
	ClientID   string    `orm:"size(64);null"`
	CommonName string    `orm:"size(128);index"`
	RealAddr   string    `orm:"size(128);null"`
	VirtAddr   string    `orm:"size(128);null"`
	EventType  string    `orm:"size(64);index"`
	Reason     string    `orm:"size(256);null"`
	Details    string    `orm:"type(text);null"`
}

// RoutingCCD stores CCD/iroute snapshot derived from routing table or CCD
// scans.
type RoutingCCD struct {
	Id         int64
	ClientID   string    `orm:"size(64);null"`
	CommonName string    `orm:"size(128);null"`
	Net        string    `orm:"size(64);index"`
	Mask       string    `orm:"size(64);null"`
	SeenAt     time.Time `orm:"auto_now_add;type(datetime);index"`
	Source     string    `orm:"size(32);index"`
}

// DaemonInfo keeps latest daemon snapshot.
type DaemonInfo struct {
	Id        int64
	Pid       int64     `orm:"index"`
	Version   string    `orm:"size(128);null"`
	BuildInfo string    `orm:"type(text);null"`
	LastSeen  time.Time `orm:"auto_now;type(datetime);index"`
}

// SaveMetricSamples persists metric samples into the dedicated metrics database.
func SaveMetricSamples(samples []MetricSample) error {
	if len(samples) == 0 {
		return nil
	}

	o := orm.NewOrmUsingDB(metricsAlias)
	for i := range samples {
		if _, err := o.Insert(&samples[i]); err != nil {
			return err
		}
	}
	return nil
}

// MakeClientLookupKey builds deterministic lookup key for ClientSession upserts.
func MakeClientLookupKey(clientID, commonName, realAddr, virtAddr string) string {
	if clientID != "" {
		return clientID
	}
	return commonName + "|" + realAddr + "|" + virtAddr
}

// UpsertClientSession inserts or updates ClientSession by LookupKey.
func UpsertClientSession(session *ClientSession) error {
	o := orm.NewOrmUsingDB(metricsAlias)
	existing := ClientSession{}
	if err := o.QueryTable(new(ClientSession)).Filter("LookupKey", session.LookupKey).One(&existing); err == nil {
		session.Id = existing.Id
		_, err = o.Update(session)
		return err
	}
	_, err := o.Insert(session)
	return err
}

// SaveClientEvents stores event records.
func SaveClientEvents(events []ClientEvent) error {
	if len(events) == 0 {
		return nil
	}
	o := orm.NewOrmUsingDB(metricsAlias)
	for i := range events {
		if _, err := o.Insert(&events[i]); err != nil {
			return err
		}
	}
	return nil
}

// SaveRoutingCCD stores routing/ccd snapshots.
func SaveRoutingCCD(entries []RoutingCCD) error {
	if len(entries) == 0 {
		return nil
	}
	o := orm.NewOrmUsingDB(metricsAlias)
	for i := range entries {
		if _, err := o.Insert(&entries[i]); err != nil {
			return err
		}
	}
	return nil
}

// UpsertDaemonInfo keeps single daemon row per PID.
func UpsertDaemonInfo(info *DaemonInfo) error {
	o := orm.NewOrmUsingDB(metricsAlias)
	if info.Id == 0 {
		// ensure we reuse existing row for same pid
		existing := DaemonInfo{}
		if err := o.QueryTable(new(DaemonInfo)).Filter("Pid", info.Pid).One(&existing); err == nil {
			info.Id = existing.Id
		}
	}
	if info.Id > 0 {
		if _, err := o.Update(info); err == nil {
			return nil
		}
	}
	_, err := o.Insert(info)
	return err
}

// MarshalLabels converts labels to json string.
func MarshalLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	data, err := json.Marshal(labels)
	if err != nil {
		return ""
	}
	return string(data)
}
