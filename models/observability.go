package models

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego/v2/client/orm"
)

// MetricSample stores raw metric points collected from OpenVPN management
// interface or OS probes. LabelsJSON keeps dynamic labels like common_name,
// real_addr, virt_addr, peer_id, tls params, etc.
type MetricSample struct {
	Id         int64
	Name       string `orm:"size(128);index;unique(name_source_time_hash)"`
	Value      float64
	Unit       string    `orm:"size(64);null"`
	LabelsJSON string    `orm:"type(text);null"`
	LabelsHash string    `orm:"size(64);index;unique(name_source_time_hash)"`
	RecordedAt time.Time `orm:"auto_now_add;type(datetime);index;unique(name_source_time_hash)"`
	Source     string    `orm:"size(32);index;unique(name_source_time_hash)"`
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
	ClientID   string    `orm:"size(64);null;index"`
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
	ClientID   string    `orm:"size(64);null;index"`
	CommonName string    `orm:"size(128);null"`
	Net        string    `orm:"size(64);index;unique(route_seen)"`
	Mask       string    `orm:"size(64);null"`
	SeenAt     time.Time `orm:"auto_now_add;type(datetime);index;unique(route_seen)"`
	Source     string    `orm:"size(32);index"`
}

// DaemonInfo keeps latest daemon snapshot.
type DaemonInfo struct {
	Id          int64
	Pid         int64     `orm:"index"`
	Version     string    `orm:"size(128);null"`
	BuildInfo   string    `orm:"type(text);null"`
	DaemonStart time.Time `orm:"null;type(datetime);index"`
	LastSeen    time.Time `orm:"auto_now;type(datetime);index"`
}

// SaveMetricSamples persists metric samples into the dedicated metrics database.
func SaveMetricSamples(samples []MetricSample) error {
	o := orm.NewOrmUsingDB(metricsAlias)
	tx, err := o.Begin()
	if err != nil {
		return err
	}
	if err := saveMetricSamplesWithOrm(txOrmerAdapter{tx}, samples); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// SaveMetricSamplesWithOrm persists metrics using provided Ormer (expects caller to manage transaction lifecycle).
func SaveMetricSamplesWithOrm(o orm.Ormer, samples []MetricSample) error {
	return saveMetricSamplesWithOrm(o, samples)
}

// MakeClientLookupKey builds deterministic lookup key for ClientSession upserts.
func MakeClientLookupKey(clientID, commonName, realAddr, virtAddr string) string {
	idPart := clientID
	if strings.TrimSpace(idPart) == "" {
		idPart = "-1"
	}
	return commonName + "|" + idPart + "|" + realAddr + "|" + virtAddr
}

// UpsertClientSession inserts or updates ClientSession by LookupKey.
func UpsertClientSession(session *ClientSession) error {
	o := orm.NewOrmUsingDB(metricsAlias)
	return UpsertClientSessionWithOrm(o, session)
}

// UpsertClientSessionWithOrm updates or inserts session preserving existing timestamps when absent.
func UpsertClientSessionWithOrm(o orm.Ormer, session *ClientSession) error {
	existing := ClientSession{}
	if err := o.QueryTable(new(ClientSession)).Filter("LookupKey", session.LookupKey).One(&existing); err == nil {
		session.Id = existing.Id
		if session.ConnectedSince.IsZero() {
			session.ConnectedSince = existing.ConnectedSince
		}
		if session.LastRef.IsZero() {
			session.LastRef = existing.LastRef
		}
		_, err = o.Update(session)
		return err
	}
	_, err := o.Insert(session)
	return err
}

// SaveClientEvents stores event records.
func SaveClientEvents(events []ClientEvent) error {
	o := orm.NewOrmUsingDB(metricsAlias)
	return SaveClientEventsWithOrm(o, events)
}

// SaveRoutingCCD stores routing/ccd snapshots.
func SaveClientEventsWithOrm(o orm.Ormer, events []ClientEvent) error {
	if len(events) == 0 {
		return nil
	}
	for i := range events {
		if _, err := o.Insert(&events[i]); err != nil {
			return err
		}
	}
	return nil
}

// SaveRoutingCCD upserts routing/ccd snapshots by (common_name, net).
func SaveRoutingCCD(entries []RoutingCCD) error {
	o := orm.NewOrmUsingDB(metricsAlias)
	return SaveRoutingCCDWithOrm(o, entries)
}

// SaveRoutingCCDWithOrm performs routing upserts using provided Ormer.
func SaveRoutingCCDWithOrm(o orm.Ormer, entries []RoutingCCD) error {
	if len(entries) == 0 {
		return nil
	}
	for i := range entries {
		entry := entries[i]
		query := `INSERT INTO routing_c_c_d (client_id, common_name, net, mask, seen_at, source) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(common_name, net) DO UPDATE SET
client_id=excluded.client_id,
mask=excluded.mask,
source=excluded.source,
seen_at=CASE WHEN excluded.seen_at > routing_c_c_d.seen_at THEN excluded.seen_at ELSE routing_c_c_d.seen_at END`
		if _, err := o.Raw(query, entry.ClientID, entry.CommonName, entry.Net, entry.Mask, entry.SeenAt, entry.Source).Exec(); err != nil {
			return err
		}
	}
	return nil
}

// UpsertDaemonInfo keeps single daemon row per PID.
func UpsertDaemonInfo(info *DaemonInfo) error {
	o := orm.NewOrmUsingDB(metricsAlias)
	return UpsertDaemonInfoWithOrm(o, info)
}

// UpsertDaemonInfoWithOrm keeps single daemon row per PID when available.
func UpsertDaemonInfoWithOrm(o orm.Ormer, info *DaemonInfo) error {
	existing := DaemonInfo{}
	if info.Pid > 0 {
		if err := o.QueryTable(new(DaemonInfo)).Filter("Pid", info.Pid).One(&existing); err == nil {
			info.Id = existing.Id
		}
	}
	if info.Id == 0 {
		if err := o.QueryTable(new(DaemonInfo)).OrderBy("-LastSeen").One(&existing); err == nil {
			info.Id = existing.Id
			if info.Pid == 0 {
				info.Pid = existing.Pid
			}
			if info.DaemonStart.IsZero() {
				info.DaemonStart = existing.DaemonStart
			}
		}
	}
	info.LastSeen = info.LastSeen.UTC()
	if info.DaemonStart.After(time.Time{}) {
		info.DaemonStart = info.DaemonStart.UTC()
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

	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := &bytes.Buffer{}
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		v, _ := json.Marshal(labels[k])
		buf.WriteString("\"")
		buf.WriteString(k)
		buf.WriteString("\":")
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.String()
}

const (
	maxBatchSize       = 200
	minGaugeInterval   = 30 * time.Second
	metricCacheTimeout = 10 * time.Minute
)

type metricCacheEntry struct {
	value      float64
	recordedAt time.Time
	metricType string
}

var (
	metricCache   = map[string]metricCacheEntry{}
	metricCacheMu sync.Mutex
)

func normalizeMetricSamples(samples []MetricSample) []MetricSample {
	now := time.Now().UTC()
	filtered := make([]MetricSample, 0, len(samples))

	metricCacheMu.Lock()
	defer metricCacheMu.Unlock()

	for i := range samples {
		sample := samples[i]
		if sample.RecordedAt.IsZero() {
			sample.RecordedAt = now
		} else {
			sample.RecordedAt = sample.RecordedAt.UTC()
		}
		sample.LabelsHash = computeLabelsHash(sample.LabelsJSON)

		cacheKey := sample.Name + "|" + sample.Source + "|" + sample.LabelsHash
		entry, ok := metricCache[cacheKey]

		shouldInsert := true
		if ok {
			if sample.MetricType == "counter" {
				shouldInsert = sample.Value > entry.value
			} else {
				shouldInsert = sample.Value != entry.value || sample.RecordedAt.Sub(entry.recordedAt) >= minGaugeInterval
			}
		}

		if shouldInsert {
			filtered = append(filtered, sample)
			metricCache[cacheKey] = metricCacheEntry{value: sample.Value, recordedAt: sample.RecordedAt, metricType: sample.MetricType}
		}
	}

	// opportunistic cleanup
	cutoff := now.Add(-metricCacheTimeout)
	for key, entry := range metricCache {
		if entry.recordedAt.Before(cutoff) {
			delete(metricCache, key)
		}
	}

	return filtered
}

func insertMetricSamples(o orm.Ormer, samples []MetricSample) error {
	for start := 0; start < len(samples); start += maxBatchSize {
		end := start + maxBatchSize
		if end > len(samples) {
			end = len(samples)
		}
		batch := samples[start:end]
		if _, err := o.InsertMulti(len(batch), batch); err != nil {
			return err
		}
	}
	return nil
}

func computeLabelsHash(labelsJSON string) string {
	h := sha256.Sum256([]byte(labelsJSON))
	return hex.EncodeToString(h[:])
}

func saveMetricSamplesWithOrm(o orm.Ormer, samples []MetricSample) error {
	filtered := normalizeMetricSamples(samples)
	if len(filtered) == 0 {
		return nil
	}
	return insertMetricSamples(o, filtered)
}
