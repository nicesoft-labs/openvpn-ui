package lib

import (
	"reflect"
	"testing"
	"time"
)

func TestParseStatusSnapshotV3(t *testing.T) {
	raw := "" +
		"TITLE,OpenVPN 2.6\n" +
		"TIME,Thu Jun 20 00:00:00 2024,1718841600\n" +
		"HEADER,CLIENT_LIST,Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher,Virtual Address,Virtual IPv6\n" +
		"CLIENT_LIST,client1,198.51.100.10:1194,1024,2048,Thu Jun 20 00:00:00 2024,1718841600,user1,5,1,AES-256-GCM,10.0.0.2,fd00::2\n" +
		"HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref,Last Ref (time_t),Client ID,Peer ID\n" +
		"ROUTING_TABLE,10.0.0.2,client1,198.51.100.10:1194,Thu Jun 20 00:00:05 2024,1718841605,5,1\n" +
		"GLOBAL_STATS,MaxBcastMcastQueueLen,7\n"

	snap, err := ParseStatusSnapshot(raw)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if snap.Title == "" || len(snap.Clients) != 1 || len(snap.Routes) != 1 {
		t.Fatalf("unexpected snapshot %+v", snap)
	}
	if snap.Time.Unix() != 1718841600 {
		t.Fatalf("unexpected time: %v", snap.Time)
	}
	if got := snap.GlobalStats["maxbcastmcastqueuelen"]; got != 7 {
		t.Fatalf("global stat mismatch: %v", got)
	}
	client := snap.Clients[0]
	if client.CommonName != "client1" || client.ClientID != "5" || client.PeerID != "1" {
		t.Fatalf("unexpected client data: %+v", client)
	}
	if client.Connected.Unix() != 1718841600 {
		t.Fatalf("connected time mismatch: %v", client.Connected)
	}
	route := snap.Routes[0]
	if route.VirtAddr != "10.0.0.2" || route.ClientID != "5" || route.PeerID != "1" {
		t.Fatalf("route mismatch: %+v", route)
	}
}

func TestParseStatusSnapshotV2(t *testing.T) {
	raw := "" +
		"TITLE,OpenVPN 2.x\n" +
		"TIME,Thu Jun 20 00:00:00 2024,1718841600\n" +
		"CLIENT_LIST,client2,203.0.113.5:1194,10.1.0.2,fd00::3,512,256,Thu Jun 20 00:00:00 2024,1718841600,user2,6,2,AES-128-GCM\n" +
		"ROUTING_TABLE,10.1.0.2,client2,203.0.113.5:1194,Thu Jun 20 00:00:10 2024,1718841610\n"

	snap, err := ParseStatusSnapshot(raw)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(snap.Clients) != 1 || len(snap.Routes) != 1 {
		t.Fatalf("unexpected snapshot sizes: %+v", snap)
	}
	if snap.Clients[0].VirtAddr != "10.1.0.2" || snap.Routes[0].VirtAddr != "10.1.0.2" {
		t.Fatalf("virtual address mismatch")
	}
}

func TestParseLoadStats(t *testing.T) {
	raw := "SUCCESS: nclients=2,bytesin=10,bytesout=20,uptime=30"
	stats, err := ParseLoadStats(raw)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if stats.Uptime != 30 || stats.NClients != 2 || stats.BytesIn != 10 || stats.BytesOut != 20 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestParseBytecountLine(t *testing.T) {
	sample, ok := ParseBytecountLine(">BYTECOUNT_CLI:clientA,100,200")
	if !ok || sample.CommonName != "clientA" || sample.BytesOut != 100 || sample.BytesIn != 200 {
		t.Fatalf("unexpected sample: %+v", sample)
	}

	sample, ok = ParseBytecountLine(">BYTECOUNT_CLI:9,clientB,300,400")
	if !ok || sample.ClientID != "9" || sample.BytesOut != 300 || sample.BytesIn != 400 {
		t.Fatalf("unexpected sample 2: %+v", sample)
	}
}

func TestParsePeerInfo(t *testing.T) {
	raw := "IV_PLAT=linux\nIV_VER=2.6\nIV_GUI_VER=3.4\nUSERNAME=test"
	labels := ParsePeerInfo(raw)
	expected := map[string]string{"iv_plat": "linux", "iv_ver": "2.6", "iv_gui_ver": "3.4", "username": "test"}
	if !reflect.DeepEqual(labels, expected) {
		t.Fatalf("labels mismatch: %+v", labels)
	}
}

func TestNormalizeAddr(t *testing.T) {
	addr := NormalizeAddr("198.51.100.10:1194")
	if addr != "198.51.100.10" {
		t.Fatalf("normalize failed: %s", addr)
	}
	plain := NormalizeAddr("198.51.100.10")
	if plain != "198.51.100.10" {
		t.Fatalf("normalize passthrough failed: %s", plain)
	}
}

func TestParseStateEvent(t *testing.T) {
	line := ">STATE:1718841600,CONNECTED,SUCCESS,198.51.100.10:1194,clientA,client-id=7,peer-id=1,virtual=10.0.0.2"
	evt, ok := parseStateEvent(line)
	if !ok {
		t.Fatalf("expected event to parse")
	}
	if evt.Event != "CONNECTED" || evt.ClientID != "7" || evt.PeerID != "1" || evt.VirtAddr != "10.0.0.2" {
		t.Fatalf("unexpected event: %+v", evt)
	}
	if evt.Recorded.Unix() != 1718841600 {
		t.Fatalf("unexpected ts: %v", evt.Recorded)
	}
}

func TestSplitRouteWithMask(t *testing.T) {
	ip, mask := splitRouteWithMask("10.0.0.0/24")
	if ip != "10.0.0.0" || mask != "24" {
		t.Fatalf("unexpected split: %s %s", ip, mask)
	}
	ip, mask = splitRouteWithMask("10.0.0.5")
	if mask != "255.255.255.255" {
		t.Fatalf("expected host mask, got %s", mask)
	}
}

func TestParseUnixSafe(t *testing.T) {
	ts := parseUnixSafe("1718841600")
	if ts.Unix() != 1718841600 {
		t.Fatalf("timestamp mismatch")
	}
	readable := parseUnixSafe("Thu Jun 20 00:00:00 2024")
	if readable.IsZero() {
		t.Fatalf("expected parsed time")
	}
	zero := parseUnixSafe("")
	if !zero.IsZero() {
		t.Fatalf("expected zero time")
	}
}

func TestFirstNotEmpty(t *testing.T) {
	if got := firstNotEmpty("", " ", "ok", "skip"); got != "ok" {
		t.Fatalf("unexpected value: %s", got)
	}
	if firstNotEmpty("", " ") != "" {
		t.Fatalf("expected empty")
	}
}

func TestCollectPeerLabels(t *testing.T) {
	collector := NewObservabilityCollector()
	collector.updatePeerInfo("1", "client", map[string]string{"iv_plat": "linux"})
	labels := collector.collectPeerLabels("1", "client")
	if labels["iv_plat"] != "linux" {
		t.Fatalf("missing label")
	}
}

func TestParseLoadStatsMissingUptime(t *testing.T) {
	raw := "SUCCESS: nclients=1,bytesin=2,bytesout=3"
	stats, err := ParseLoadStats(raw)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if stats.Uptime != 0 {
		t.Fatalf("expected zero uptime, got %d", stats.Uptime)
	}
}

func TestStatusParsingEmpty(t *testing.T) {
	if _, err := ParseStatusSnapshot(""); err == nil {
		t.Fatalf("expected error on empty snapshot")
	}
}

func TestParseBytecountLineInvalid(t *testing.T) {
	if _, ok := ParseBytecountLine(">BYTECOUNT_CLI:bad"); ok {
		t.Fatalf("expected parse to fail")
	}
}

func TestParsePeerInfoEmpty(t *testing.T) {
	labels := ParsePeerInfo("#comment")
	if len(labels) != 0 {
		t.Fatalf("expected empty map")
	}
}

func TestStatusSnapshotRoutesCaseInsensitiveHeader(t *testing.T) {
	raw := "HEADER,ROUTING_TABLE,VIRTUAL ADDRESS,COMMON NAME,REAL ADDRESS,LAST REF,LAST REF (TIME_T)\nROUTING_TABLE,10.10.0.2,client,203.0.113.9:1194,Thu Jun 20 00:00:00 2024,1718841600\n"
	snap, err := ParseStatusSnapshot(raw)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(snap.Routes) != 1 || snap.Routes[0].LastRef.IsZero() {
		t.Fatalf("route parsing failed: %+v", snap.Routes)
	}
}

func TestNormalizeAddrInvalid(t *testing.T) {
	addr := NormalizeAddr("[::1]")
	if addr != "[::1]" {
		t.Fatalf("expected passthrough for invalid split")
	}
}

func TestParseStatusSnapshotTimeFallback(t *testing.T) {
	raw := "CLIENT_LIST,client1,198.51.100.10:1194,1024,2048,Thu Jun 20 00:00:00 2024,1718841600,user1,5,1,AES-256-GCM,10.0.0.2,fd00::2\n"
	snap, err := ParseStatusSnapshot(raw)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(snap.Clients) != 1 {
		t.Fatalf("expected client entry")
	}
}

func TestStateEventWithoutKV(t *testing.T) {
	line := ">STATE:1718841600,EXITING,SIGTERM"
	evt, ok := parseStateEvent(line)
	if !ok || evt.Event != "EXITING" || evt.Reason != "SIGTERM" {
		t.Fatalf("unexpected event: %+v", evt)
	}
}

func TestLoadStatsUnexpected(t *testing.T) {
	if _, err := ParseLoadStats("bad payload"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestPeerInfoLowercases(t *testing.T) {
	info := ParsePeerInfo("IV_PLAT=Linux\nIv_Proto=udp")
	if info["iv_plat"] != "Linux" || info["iv_proto"] != "udp" {
		t.Fatalf("unexpected labels: %+v", info)
	}
}

func TestStatusSnapshotGlobalStats(t *testing.T) {
	raw := "GLOBAL_STATS,MaxBcastMcastQueueLen,5\n"
	snap, err := ParseStatusSnapshot(raw)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if snap.GlobalStats["maxbcastmcastqueuelen"] != 5 {
		t.Fatalf("expected global stat")
	}
}

func TestStatusSnapshotRouteFallbackMask(t *testing.T) {
	r, m := splitRouteWithMask("10.0.0.4-255.255.255.0")
	if r != "10.0.0.4" || m != "255.255.255.0" {
		t.Fatalf("unexpected route split: %s %s", r, m)
	}
}

func TestParseLoadStatsWhitespace(t *testing.T) {
	raw := " SUCCESS: nclients=3,bytesin=4,bytesout=5,uptime=6 "
	stats, err := ParseLoadStats(raw)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if stats.Uptime != 6 || stats.NClients != 3 || stats.BytesIn != 4 || stats.BytesOut != 5 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestStatusSnapshotRouteCommon(t *testing.T) {
	raw := "ROUTING_TABLE,10.10.0.2,clientB,203.0.113.3:1194,Thu Jun 20 00:00:00 2024,1718841600,12,1\n"
	snap, err := ParseStatusSnapshot(raw)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(snap.Routes) != 1 || snap.Routes[0].ClientID != "12" || snap.Routes[0].PeerID != "1" {
		t.Fatalf("unexpected route data: %+v", snap.Routes[0])
	}
}

func TestStatusSnapshotTimeParsing(t *testing.T) {
	raw := "TIME,Thu Jun 20 00:00:00 2024,1718841600\n"
	snap, err := ParseStatusSnapshot(raw)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if snap.Time.Unix() != time.Unix(1718841600, 0).Unix() {
		t.Fatalf("unexpected parsed time: %v", snap.Time)
	}
}
