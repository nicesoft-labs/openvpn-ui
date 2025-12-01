package lib

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// StatusSnapshot captures parsed output of `status 2/3` command including optional
// GLOBAL_STATS entries introduced in OpenVPN 2.6.17.
type StatusSnapshot struct {
	Title       string
	Time        time.Time
	TimeRaw     string
	Clients     []ClientStatus
	Routes      []RouteStatus
	GlobalStats map[string]float64
}

// ClientStatus contains client level information from CLIENT_LIST table.
type ClientStatus struct {
	CommonName string
	RealAddr   string
	VirtAddr   string
	VirtAddr6  string
	Username   string
	ClientID   string
	PeerID     string
	DataCipher string
	BytesRecv  uint64
	BytesSent  uint64
	Connected  time.Time
}

// RouteStatus maps routing table rows to virtual addresses.
type RouteStatus struct {
	VirtAddr string
	Common   string
	RealAddr string
	LastRef  time.Time
	ClientID string
	PeerID   string
}

// LoadStatsSnapshot extends `load-stats` parsing with daemon uptime seconds.
type LoadStatsSnapshot struct {
	NClients int64
	BytesIn  int64
	BytesOut int64
	Uptime   int64
}

// BytecountSample describes >BYTECOUNT_CLI lines.
type BytecountSample struct {
	CommonName string
	ClientID   string
	BytesIn    uint64
	BytesOut   uint64
}

// ParseStatusSnapshot handles both status 2 and status 3 output.
func ParseStatusSnapshot(raw string) (*StatusSnapshot, error) {
	snapshot := &StatusSnapshot{Clients: []ClientStatus{}, Routes: []RouteStatus{}, GlobalStats: map[string]float64{}}
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty status payload")
	}

	headers := map[string][]string{}
	for _, line := range lines {
		fields := strings.Split(strings.TrimSpace(line), ",")
		if len(fields) == 0 {
			continue
		}
		kind := fields[0]
		switch kind {
		case "TITLE":
			if len(fields) > 1 {
				snapshot.Title = fields[1]
			}
		case "TIME":
			if len(fields) > 2 {
				snapshot.TimeRaw = fields[1]
				snapshot.Time = parseUnixSafe(fields[2])
			}
		case "HEADER":
			if len(fields) > 2 {
				headers[fields[1]] = fields[2:]
			}
		case "CLIENT_LIST":
			client, err := parseClientList(fields, headers["CLIENT_LIST"])
			if err != nil {
				return nil, err
			}
			snapshot.Clients = append(snapshot.Clients, client)
		case "ROUTING_TABLE":
			route, err := parseRoute(fields, headers["ROUTING_TABLE"])
			if err != nil {
				return nil, err
			}
			snapshot.Routes = append(snapshot.Routes, route)
		case "GLOBAL_STATS":
			if len(fields) >= 3 {
				key := strings.ToLower(fields[1])
				val, _ := strconv.ParseFloat(fields[2], 64)
				snapshot.GlobalStats[key] = val
			}
		}
	}

	return snapshot, nil
}

func parseClientList(fields, header []string) (ClientStatus, error) {
	idx := make(map[string]int)
	for i, h := range header {
		idx[strings.ToLower(h)] = i + 1
	}
	pull := func(name string) string {
		if pos, ok := idx[name]; ok && pos < len(fields) {
			return fields[pos]
		}
		return ""
	}

	// status 2 fallback positional mapping
	if len(header) == 0 {
		header = []string{"Common Name", "Real Address", "Virtual Address", "Virtual IPv6", "Bytes Received", "Bytes Sent", "Connected Since", "Connected Since (time_t)", "Username", "Client ID", "Peer ID", "Data Channel Cipher"}
		return parseClientList(fields, header)
	}

	bytesRecv, _ := strconv.ParseUint(strings.TrimSpace(pull("bytes received")), 10, 64)
	bytesSent, _ := strconv.ParseUint(strings.TrimSpace(pull("bytes sent")), 10, 64)
	connected := parseUnixSafe(pull("connected since (time_t)"))

	return ClientStatus{
		CommonName: strings.TrimSpace(pull("common name")),
		RealAddr:   strings.TrimSpace(pull("real address")),
		VirtAddr:   strings.TrimSpace(pull("virtual address")),
		VirtAddr6:  strings.TrimSpace(pull("virtual ipv6")),
		Username:   strings.TrimSpace(pull("username")),
		ClientID:   strings.TrimSpace(pull("client id")),
		PeerID:     strings.TrimSpace(pull("peer id")),
		DataCipher: strings.TrimSpace(pull("data channel cipher")),
		BytesRecv:  bytesRecv,
		BytesSent:  bytesSent,
		Connected:  connected,
	}, nil
}

func parseRoute(fields, header []string) (RouteStatus, error) {
	idx := make(map[string]int)
	for i, h := range header {
		idx[strings.ToLower(h)] = i + 1
	}
	pull := func(name string) string {
		if pos, ok := idx[name]; ok && pos < len(fields) {
			return fields[pos]
		}
		return ""
	}

	if len(header) == 0 {
		header = []string{"Virtual Address", "Common Name", "Real Address", "Last Ref", "Last Ref (time_t)"}
		return parseRoute(fields, header)
	}

	return RouteStatus{
		VirtAddr: strings.TrimSpace(pull("virtual address")),
		Common:   strings.TrimSpace(pull("common name")),
		RealAddr: strings.TrimSpace(pull("real address")),
		LastRef:  parseUnixSafe(pull("last ref (time_t)")),
		ClientID: strings.TrimSpace(pull("client id")),
		PeerID:   strings.TrimSpace(pull("peer id")),
	}, nil
}

// ParseLoadStats extracts nclients/bytes and optional uptime from load-stats output.
func ParseLoadStats(raw string) (*LoadStatsSnapshot, error) {
	line := strings.TrimSpace(raw)
	parts := strings.Split(strings.TrimPrefix(line, "SUCCESS: "), ",")
	if len(parts) < 3 {
		return nil, fmt.Errorf("unexpected load-stats payload: %s", raw)
	}

	snapshot := &LoadStatsSnapshot{}
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "nclients":
			snapshot.NClients, _ = strconv.ParseInt(kv[1], 10, 64)
		case "bytesin":
			snapshot.BytesIn, _ = strconv.ParseInt(kv[1], 10, 64)
		case "bytesout":
			snapshot.BytesOut, _ = strconv.ParseInt(kv[1], 10, 64)
		case "uptime":
			snapshot.Uptime, _ = strconv.ParseInt(kv[1], 10, 64)
		}
	}

	return snapshot, nil
}

// ParseBytecountLine parses management \n>BYTECOUNT_CLI lines.
func ParseBytecountLine(line string) (BytecountSample, bool) {
	payload := strings.TrimPrefix(line, ">BYTECOUNT_CLI:")
	fields := strings.Split(strings.TrimSpace(payload), ",")
	switch len(fields) {
	case 3:
		in, errIn := strconv.ParseUint(fields[2], 10, 64)
		out, errOut := strconv.ParseUint(fields[1], 10, 64)
		if errIn != nil || errOut != nil {
			return BytecountSample{}, false
		}
		return BytecountSample{CommonName: fields[0], BytesIn: in, BytesOut: out}, true
	case 4:
		in, errIn := strconv.ParseUint(fields[3], 10, 64)
		out, errOut := strconv.ParseUint(fields[2], 10, 64)
		if errIn != nil || errOut != nil {
			return BytecountSample{}, false
		}
		return BytecountSample{ClientID: fields[0], CommonName: fields[1], BytesIn: in, BytesOut: out}, true
	default:
		return BytecountSample{}, false
	}
}

// ParsePeerInfo turns peer-info output into key/value labels.
func ParsePeerInfo(raw string) map[string]string {
	labels := map[string]string{}
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	for _, line := range lines {
		if !strings.Contains(line, "=") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		labels[key] = val
	}
	return labels
}

func parseUnixSafe(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if ts, err := strconv.ParseInt(raw, 10, 64); err == nil && ts > 0 {
		return time.Unix(ts, 0)
	}
	if t, err := time.Parse(time.ANSIC, raw); err == nil {
		return t
	}
	return time.Time{}
}

// NormalizeAddr strips trailing port if present.
func NormalizeAddr(raw string) string {
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		return raw
	}
	return host
}
