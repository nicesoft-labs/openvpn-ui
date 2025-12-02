package lib

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/beego/beego/v2/core/logs"
)

const topN = 10

// NetInfo aggregates network telemetry snapshot.
type NetInfo struct {
	Ifaces         []NetInterface `json:"ifaces,omitempty"`
	Softnet        SoftnetStat    `json:"softnet,omitempty"`
	SNMP           SNMPStats      `json:"snmp,omitempty"`
	Conntrack      ConntrackStat  `json:"conntrack,omitempty"`
	TCPStates      TCPStates      `json:"tcp_states,omitempty"`
	UDPMemLimits   UDPMemLimits   `json:"udp_mem_limits,omitempty"`
	UDPPortStats   []UDPPortStat  `json:"udp_port_stats,omitempty"`
	TCPSocketStats TCPSocketStats `json:"tcp_socket_stats,omitempty"`
	SockStat       SockStat       `json:"sock_stat,omitempty"`
	SockStat6      SockStat       `json:"sock_stat6,omitempty"`
	SchemaVersion  int            `json:"schema_version,omitempty"`
	Warnings       []string       `json:"warnings,omitempty"`
}

// NetInterface represents counters and metadata for a network interface.
type NetInterface struct {
	Name            string  `json:"name"`
	MAC             string  `json:"mac,omitempty"`
	MTU             *int    `json:"mtu,omitempty"`
	OperState       string  `json:"operstate,omitempty"`
	Down            bool    `json:"down,omitempty"`
	SpeedMbps       *int64  `json:"speed_mbps,omitempty"`
	Duplex          string  `json:"duplex,omitempty"`
	QDisc           string  `json:"qdisc,omitempty"`
	RxBytes         *uint64 `json:"rx_bytes,omitempty"`
	TxBytes         *uint64 `json:"tx_bytes,omitempty"`
	RxPackets       *uint64 `json:"rx_packets,omitempty"`
	TxPackets       *uint64 `json:"tx_packets,omitempty"`
	RxErrors        *uint64 `json:"rx_errors,omitempty"`
	TxErrors        *uint64 `json:"tx_errors,omitempty"`
	RxDropped       *uint64 `json:"rx_dropped,omitempty"`
	TxDropped       *uint64 `json:"tx_dropped,omitempty"`
	RxFifoErrors    *uint64 `json:"rx_fifo_errors,omitempty"`
	TxFifoErrors    *uint64 `json:"tx_fifo_errors,omitempty"`
	RxFrameErrors   *uint64 `json:"rx_frame_errors,omitempty"`
	TxCarrierErrors *uint64 `json:"tx_carrier_errors,omitempty"`
	Multicast       *uint64 `json:"multicast,omitempty"`
}

// SoftnetCPU describes softnet stats per CPU.
type SoftnetCPU struct {
	CPU            int     `json:"cpu"`
	Processed      uint64  `json:"processed"`
	Dropped        uint64  `json:"dropped"`
	TimeSqueezed   uint64  `json:"time_squeezed"`
	FlowLimitCount uint64  `json:"flow_limit_count"`
}

// SoftnetTotal contains aggregated softnet stats across CPUs.
type SoftnetTotal struct {
	Processed      uint64 `json:"processed"`
	Dropped        uint64 `json:"dropped"`
	TimeSqueezed   uint64 `json:"time_squeezed"`
	FlowLimitCount uint64 `json:"flow_limit_count"`
}

// SoftnetStat contains per-CPU and total softnet stats.
type SoftnetStat struct {
	PerCPU []SoftnetCPU `json:"per_cpu,omitempty"`
	Total  SoftnetTotal `json:"total"`
}

// SNMPStats aggregates TCP/UDP stats and TCPExt where available.
type SNMPStats struct {
	TCP      map[string]uint64 `json:"tcp,omitempty"`
	UDP      map[string]uint64 `json:"udp,omitempty"`
	UDP6     map[string]uint64 `json:"udp6,omitempty"`
	UDPLite  map[string]uint64 `json:"udplite,omitempty"`
	UDPLite6 map[string]uint64 `json:"udplite6,omitempty"`
	TCPExt   map[string]uint64 `json:"tcpext,omitempty"`
	SNMP6    map[string]uint64 `json:"snmp6,omitempty"`
}

// ConntrackStat holds conntrack counters.
type ConntrackStat struct {
	Count           *uint64 `json:"count,omitempty"`
	Max             *uint64 `json:"max,omitempty"`
	Buckets         *uint64 `json:"buckets,omitempty"`
	Checksum        *uint64 `json:"checksum,omitempty"`
	TCPLoose        *uint64 `json:"tcp_loose,omitempty"`
	GenericTimeout  *uint64 `json:"generic_timeout,omitempty"`
	ExpectMax       *uint64 `json:"expect_max,omitempty"`
}

// TCPStates aggregates TCP socket counts per state.
type TCPStates struct {
	Listen      uint64 `json:"listen"`
	Established uint64 `json:"established"`
	SynSent     uint64 `json:"syn_sent"`
	SynRecv     uint64 `json:"syn_recv"`
	FinWait1    uint64 `json:"fin_wait1"`
	FinWait2    uint64 `json:"fin_wait2"`
	TimeWait    uint64 `json:"time_wait"`
	Close       uint64 `json:"close"`
	CloseWait   uint64 `json:"close_wait"`
	LastAck     uint64 `json:"last_ack"`
	Closing     uint64 `json:"closing"`
	NewSynRecv  uint64 `json:"new_syn_recv"`
	Unknown     uint64 `json:"unknown"`
	Total       uint64 `json:"total"`
}

func (t TCPStates) Sum() uint64 {
	return t.Listen + t.Established + t.SynSent + t.SynRecv +
		t.FinWait1 + t.FinWait2 + t.TimeWait + t.Close +
		t.CloseWait + t.LastAck + t.Closing + t.NewSynRecv + t.Unknown
}

// UDPMemLimits holds UDP memory limits from sysctl.
type UDPMemLimits struct {
	UDPMem          []uint64 `json:"udp_mem,omitempty"` // low, pressure, high
	UDPRMemMin      uint64   `json:"udp_rmem_min,omitempty"`
	UDPWMemMin      uint64   `json:"udp_wmem_min,omitempty"`
	CoreRMemDefault uint64   `json:"core_rmem_default,omitempty"`
	CoreRMemMax     uint64   `json:"core_rmem_max,omitempty"`
	CoreWMemDefault uint64   `json:"core_wmem_default,omitempty"`
	CoreWMemMax     uint64   `json:"core_wmem_max,omitempty"`
}

// UDPPortStat aggregates stats for UDP ports.
type UDPPortStat struct {
	Port    uint16 `json:"port"`
	Count   int    `json:"count"`
	RxQueue uint64 `json:"rx_queue"`
	TxQueue uint64 `json:"tx_queue"`
	Drops   uint64 `json:"drops,omitempty"`
}

// TCPSocketStats aggregates TCP socket queue stats.
type TCPSocketStats struct {
	TotalRxQueue uint64        `json:"total_rx_queue"`
	TotalTxQueue uint64        `json:"total_tx_queue"`
	PortStats    []TCPPortStat `json:"port_stats,omitempty"`
	MaxRxQueue   *TCPPortStat  `json:"max_rx_queue,omitempty"`
	MaxTxQueue   *TCPPortStat  `json:"max_tx_queue,omitempty"`
	ActivePorts  int           `json:"active_ports,omitempty"`
}

// TCPPortStat aggregates stats for TCP ports.
type TCPPortStat struct {
	Port    uint16 `json:"port"`
	Count   int    `json:"count"`
	RxQueue uint64 `json:"rx_queue"`
	TxQueue uint64 `json:"tx_queue"`
}

// SockStat holds sockstat counters.
type SockStat struct {
	SocketsInUse uint64 `json:"sockets_inuse,omitempty"`
	TCP          SockTCP `json:"tcp,omitempty"`
	UDP          SockUDP `json:"udp,omitempty"`
	// Add other protocols as needed
}

// SockTCP holds TCP sockstat.
type SockTCP struct {
	InUse  uint64 `json:"inuse,omitempty"`
	Orphan uint64 `json:"orphan,omitempty"`
	TW     uint64 `json:"tw,omitempty"`
	Alloc  uint64 `json:"alloc,omitempty"`
	Mem    uint64 `json:"mem,omitempty"`
}

// SockUDP holds UDP sockstat.
type SockUDP struct {
	InUse uint64 `json:"inuse,omitempty"`
	Mem   uint64 `json:"mem,omitempty"`
}

// CollectNetInfo gathers network metrics snapshot.
func CollectNetInfo(ctx context.Context) (NetInfo, error) {
	netinfo := NetInfo{SchemaVersion: 2}
	var errs error

	safeCollect := func(fn func(context.Context) error) {
		if err := fn(ctx); err != nil {
			if isBenign(err) {
				netinfo.Warnings = append(netinfo.Warnings, err.Error())
				return
			}
			errs = errors.Join(errs, err)
			netinfo.Warnings = append(netinfo.Warnings, err.Error())
		}
	}

	safeCollect(func(ctx context.Context) error {
		var err error
		netinfo.Ifaces, err = collectInterfaces(ctx)
		return err
	})
	safeCollect(func(ctx context.Context) error {
		var err error
		netinfo.Softnet, err = collectSoftnet(ctx)
		return err
	})
	safeCollect(func(ctx context.Context) error {
		var err error
		netinfo.SNMP, err = collectSNMP(ctx)
		return err
	})
	safeCollect(func(ctx context.Context) error {
		var err error
		netinfo.Conntrack, err = collectConntrack(ctx)
		return err
	})
	safeCollect(func(ctx context.Context) error {
		var err error
		netinfo.TCPStates, netinfo.TCPSocketStats, err = collectTCPStatesAndStats(ctx)
		return err
	})
	safeCollect(func(ctx context.Context) error {
		var err error
		netinfo.UDPMemLimits, err = collectUDPMemLimits(ctx)
		return err
	})
	safeCollect(func(ctx context.Context) error {
		var err error
		netinfo.UDPPortStats, err = collectUDPPortStats(ctx)
		return err
	})
	safeCollect(func(ctx context.Context) error {
		var err error
		netinfo.SockStat, err = collectSockStat(ctx, "/proc/net/sockstat")
		return err
	})
	safeCollect(func(ctx context.Context) error {
		var err error
		netinfo.SockStat6, err = collectSockStat(ctx, "/proc/net/sockstat6")
		return err
	})

	return netinfo, errs
}

func isBenign(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission)
}

func collectInterfaces(ctx context.Context) ([]NetInterface, error) {
	fallback, err := parseProcNetDevFromPath(ctx, "/proc/net/dev")
	if err != nil {
		return nil, fmt.Errorf("parse proc net dev: %w", err)
	}
	names, err := listInterfaces(fallback)
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	result := make([]NetInterface, 0, len(names))
	for _, name := range names {
		iface := NetInterface{Name: name}
		basePath := filepath.Join("/sys/class/net", name)
		if mac, err := readTrimmedString(basePath + "/address"); err == nil {
			iface.MAC = mac
		}
		if mtu, err := readInt(basePath + "/mtu"); err == nil {
			m := int(mtu)
			iface.MTU = &m
		}
		if oper, err := readTrimmedString(basePath + "/operstate"); err == nil {
			iface.OperState = oper
			if oper == "down" {
				iface.Down = true
			}
		}
		if speed, err := readInt(basePath + "/speed"); err == nil {
			if speed >= 0 {
				s := int64(speed)
				iface.SpeedMbps = &s
			}
		}
		if duplex, err := readTrimmedString(basePath + "/duplex"); err == nil {
			iface.Duplex = duplex
		}
		if qdisc, err := readTrimmedString(basePath + "/qdisc"); err == nil {
			iface.QDisc = qdisc
		}
		setCounter := func(subpath string) *uint64 {
			if v, err := readUint64(basePath + "/statistics/" + subpath); err == nil {
				val := v
				return &val
			}
			return nil
		}
		iface.RxBytes = setCounter("rx_bytes")
		iface.TxBytes = setCounter("tx_bytes")
		iface.RxPackets = setCounter("rx_packets")
		iface.TxPackets = setCounter("tx_packets")
		iface.RxErrors = setCounter("rx_errors")
		iface.TxErrors = setCounter("tx_errors")
		iface.RxDropped = setCounter("rx_dropped")
		iface.TxDropped = setCounter("tx_dropped")
		iface.RxFifoErrors = setCounter("rx_fifo_errors")
		iface.TxFifoErrors = setCounter("tx_fifo_errors")
		iface.RxFrameErrors = setCounter("rx_frame_errors")
		iface.TxCarrierErrors = setCounter("tx_carrier_errors")
		iface.Multicast = setCounter("multicast")
		if fb, ok := fallback[name]; ok {
			if iface.RxBytes == nil {
				iface.RxBytes = &fb.RxBytes
			}
			if iface.TxBytes == nil {
				iface.TxBytes = &fb.TxBytes
			}
			if iface.RxPackets == nil {
				iface.RxPackets = &fb.RxPackets
			}
			if iface.TxPackets == nil {
				iface.TxPackets = &fb.TxPackets
			}
			if iface.RxErrors == nil {
				iface.RxErrors = &fb.RxErrors
			}
			if iface.TxErrors == nil {
				iface.TxErrors = &fb.TxErrors
			}
			if iface.RxDropped == nil {
				iface.RxDropped = &fb.RxDropped
			}
			if iface.TxDropped == nil {
				iface.TxDropped = &fb.TxDropped
			}
			if iface.RxFifoErrors == nil {
				iface.RxFifoErrors = &fb.RxFifoErrors
			}
			if iface.TxFifoErrors == nil {
				iface.TxFifoErrors = &fb.TxFifoErrors
			}
			if iface.RxFrameErrors == nil {
				iface.RxFrameErrors = &fb.RxFrameErrors
			}
			if iface.TxCarrierErrors == nil {
				iface.TxCarrierErrors = &fb.TxCarrierErrors
			}
			if iface.Multicast == nil {
				iface.Multicast = &fb.Multicast
			}
		}
		result = append(result, iface)
	}
	return result, nil
}

func listInterfaces(fallback map[string]procNetDevStat) ([]string, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		logs.Warn(fmt.Sprintf("cannot read /sys/class/net: %v", err))
	}
	names := make([]string, 0, len(entries))
	if err == nil {
		for _, e := range entries {
			name := e.Name()
			if name == "lo" || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") {
				continue
			}
			names = append(names, name)
		}
	}
	if len(names) == 0 && len(fallback) > 0 {
		for name := range fallback {
			if name == "lo" || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") {
				continue
			}
			names = append(names, name)
		}
	}
	return names, nil
}

type procNetDevStat struct {
	RxBytes         uint64
	TxBytes         uint64
	RxPackets       uint64
	TxPackets       uint64
	RxErrors        uint64
	TxErrors        uint64
	RxDropped       uint64
	TxDropped       uint64
	RxFifoErrors    uint64
	TxFifoErrors    uint64
	RxFrameErrors   uint64
	TxCarrierErrors uint64
	Multicast       uint64
}

func parseProcNetDev(r io.Reader) (map[string]procNetDevStat, error) {
	scanner := newScanner(r)
	stats := make(map[string]procNetDevStat)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue
		}
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 17 {
			continue
		}
		name := strings.TrimSuffix(parts[0], ":")
		var vals [16]uint64
		valid := true
		for i, p := range parts[1:17] {
			v, err := strconv.ParseUint(p, 10, 64)
			if err != nil {
				valid = false
				break
			}
			vals[i] = v
		}
		if !valid {
			continue
		}
		stats[name] = procNetDevStat{
			RxBytes:         vals[0],
			RxPackets:       vals[1],
			RxErrors:        vals[2],
			RxDropped:       vals[3],
			RxFifoErrors:    vals[4],
			RxFrameErrors:   vals[5],
			Multicast:       vals[7],
			TxBytes:         vals[8],
			TxPackets:       vals[9],
			TxErrors:        vals[10],
			TxDropped:       vals[11],
			TxFifoErrors:    vals[12],
			TxCarrierErrors: vals[14],
		}
	}
	return stats, scanner.Err()
}

func parseProcNetDevFromPath(ctx context.Context, path string) (map[string]procNetDevStat, error) {
	_, f, err := scanFile(ctx, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseProcNetDev(f)
}

func collectSoftnet(ctx context.Context) (SoftnetStat, error) {
	_, f, err := scanFile(ctx, "/proc/net/softnet_stat")
	if err != nil {
		return SoftnetStat{}, err
	}
	defer f.Close()
	perCPU, totals, err := parseSoftnet(f)
	return SoftnetStat{PerCPU: perCPU, Total: totals}, err
}

func parseSoftnet(r io.Reader) ([]SoftnetCPU, SoftnetTotal, error) {
	scanner := newScanner(r)
	perCPU := make([]SoftnetCPU, 0, 4)
	var totals SoftnetTotal
	idx := 0
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			idx++
			continue
		}
		cpuStat := SoftnetCPU{CPU: idx}
		cpuStat.Processed = parseUint(fields[0], 16)
		cpuStat.Dropped = parseUint(fields[1], 16)
		cpuStat.TimeSqueezed = parseUint(fields[2], 16)
		if len(fields) > 9 {
			cpuStat.FlowLimitCount = parseUint(fields[9], 16)
		}
		perCPU = append(perCPU, cpuStat)
		totals.Processed += cpuStat.Processed
		totals.Dropped += cpuStat.Dropped
		totals.TimeSqueezed += cpuStat.TimeSqueezed
		totals.FlowLimitCount += cpuStat.FlowLimitCount
		idx++
	}
	return perCPU, totals, scanner.Err()
}

func collectSNMP(ctx context.Context) (SNMPStats, error) {
	var stats SNMPStats
	var errs error

	safe := func(fn func() error) {
		if err := fn(); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	safe(func() error {
		var err error
		stats.TCP, err = extractSnmpSection(ctx, "/proc/net/snmp", "Tcp")
		return err
	})
	safe(func() error {
		var err error
		stats.UDP, err = extractSnmpSection(ctx, "/proc/net/snmp", "Udp")
		return err
	})
	safe(func() error {
		var err error
		stats.UDPLite, err = extractSnmpSection(ctx, "/proc/net/snmp", "UdpLite")
		return err
	})
	safe(func() error {
		var err error
		stats.TCPExt, err = extractSnmpSectionWithCases(ctx, "/proc/net/netstat", []string{"TcpExt", "TCPExt", "Tcpext"})
		return err
	})
	safe(func() error {
		var err error
		stats.SNMP6, err = collectSNMP6(ctx)
		if err == nil && stats.SNMP6 != nil {
			stats.UDP6 = make(map[string]uint64)
			stats.UDPLite6 = make(map[string]uint64)
			for k, v := range stats.SNMP6 {
				if strings.HasPrefix(k, "Udp6") {
					stats.UDP6[k[4:]] = v
				} else if strings.HasPrefix(k, "UdpLite6") {
					stats.UDPLite6[k[8:]] = v
				}
			}
		}
		return err
	})

	return stats, errs
}

func extractSnmpSection(ctx context.Context, path, section string) (map[string]uint64, error) {
	_, f, err := scanFile(ctx, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseSnmpSection(f, section)
}

func extractSnmpSectionWithCases(ctx context.Context, path string, sections []string) (map[string]uint64, error) {
	for _, section := range sections {
		m, err := extractSnmpSection(ctx, path, section)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if len(m) > 0 {
			return m, nil
		}
	}
	return nil, nil
}

func parseSnmpSection(r io.Reader, section string) (map[string]uint64, error) {
	// Takes the last occurrence as the most recent
	scanner := newScanner(r)
	var last map[string]uint64
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, section+":") {
			continue
		}
		headerLine := strings.TrimPrefix(line, section+":")
		if !scanner.Scan() {
			break
		}
		valueLine := strings.TrimPrefix(scanner.Text(), section+":")
		headers := strings.Fields(headerLine)
		values := strings.Fields(valueLine)
		if len(headers) != len(values) {
			continue
		}
		out := make(map[string]uint64, len(headers))
		for i, key := range headers {
			out[key] = parseUint(values[i], 10)
		}
		last = out
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return last, nil
}

func collectSNMP6(ctx context.Context) (map[string]uint64, error) {
	_, f, err := scanFile(ctx, "/proc/net/snmp6")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseSNMP6(f)
}

func parseSNMP6(r io.Reader) (map[string]uint64, error) {
	m := make(map[string]uint64)
	scanner := newScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 2 {
			m[parts[0]] = parseUint(parts[1], 10)
		}
	}
	return m, scanner.Err()
}

func collectConntrack(ctx context.Context) (ConntrackStat, error) {
	stat := ConntrackStat{}
	setUint := func(path string, ptr **uint64) error {
		v, err := readUint64(path)
		if err == nil {
			*ptr = &v
		}
		return err
	}
	var errs error
	errs = errors.Join(errs, setUint("/proc/sys/net/netfilter/nf_conntrack_count", &stat.Count))
	errs = errors.Join(errs, setUint("/proc/sys/net/netfilter/nf_conntrack_max", &stat.Max))
	errs = errors.Join(errs, setUint("/proc/sys/net/netfilter/nf_conntrack_buckets", &stat.Buckets))
	errs = errors.Join(errs, setUint("/proc/sys/net/netfilter/nf_conntrack_checksum", &stat.Checksum))
	errs = errors.Join(errs, setUint("/proc/sys/net/netfilter/nf_conntrack_tcp_loose", &stat.TCPLoose))
	errs = errors.Join(errs, setUint("/proc/sys/net/netfilter/nf_conntrack_generic_timeout", &stat.GenericTimeout))
	errs = errors.Join(errs, setUint("/proc/sys/net/netfilter/nf_conntrack_expect_max", &stat.ExpectMax))
	return stat, errs
}

func collectTCPStatesAndStats(ctx context.Context) (TCPStates, TCPSocketStats, error) {
	var states TCPStates
	var stats TCPSocketStats
	portMap := make(map[uint16]*TCPPortStat)
	var errs error

	parse := func(path string) error {
		_, f, err := scanFile(ctx, path)
		if err != nil {
			return err
		}
		defer f.Close()
		scanner := newScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			if lineNum == 1 {
				continue
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) < 6 {
				continue
			}
			stateHex := fields[3]
			incrementTCPState(&states, stateHex)
			txRx := strings.Split(fields[4], ":")
			if len(txRx) != 2 {
				continue
			}
			tx := parseUint(txRx[0], 16)
			rx := parseUint(txRx[1], 16)
			stats.TotalTxQueue += tx
			stats.TotalRxQueue += rx
			local := fields[1]
			parts := strings.SplitN(local, ":", 2)
			if len(parts) != 2 {
				continue
			}
			port := parseUint(parts[1], 16)
			p := uint16(port)
			portStat, ok := portMap[p]
			if !ok {
				portStat = &TCPPortStat{Port: p}
				portMap[p] = portStat
			}
			portStat.TxQueue += tx
			portStat.RxQueue += rx
			portStat.Count++
		}
		return scanner.Err()
	}
	errs = errors.Join(errs, parse("/proc/net/tcp"))
	errs = errors.Join(errs, parse("/proc/net/tcp6"))
	states.Total = states.Sum()
	var portStats []TCPPortStat
	for _, s := range portMap {
		portStats = append(portStats, *s)
	}
	sort.Slice(portStats, func(i, j int) bool {
		return portStats[i].RxQueue+portStats[i].TxQueue > portStats[j].RxQueue+portStats[j].TxQueue
	})
	if len(portStats) > topN {
		portStats = portStats[:topN]
	}
	stats.PortStats = portStats
	for i := range portStats {
		if portStats[i].RxQueue > 0 || portStats[i].TxQueue > 0 {
			stats.ActivePorts++
		}
	}
	if len(portStats) > 0 {
		maxRx := portStats[0]
		for _, p := range portStats[1:] {
			if p.RxQueue > maxRx.RxQueue {
				maxRx = p
			}
		}
		maxTx := portStats[0]
		for _, p := range portStats[1:] {
			if p.TxQueue > maxTx.TxQueue {
				maxTx = p
			}
		}
		stats.MaxRxQueue = &maxRx
		stats.MaxTxQueue = &maxTx
	}
	return states, stats, errs
}

func incrementTCPState(states *TCPStates, hexState string) {
	state := strings.ToUpper(strings.TrimSpace(hexState))
	switch state {
	case "0A":
		states.Listen++
	case "01":
		states.Established++
	case "02":
		states.SynSent++
	case "03":
		states.SynRecv++
	case "04":
		states.FinWait1++
	case "05":
		states.FinWait2++
	case "06":
		states.TimeWait++
	case "07":
		states.Close++
	case "08":
		states.CloseWait++
	case "09":
		states.LastAck++
	case "0B":
		states.Closing++
	case "0C":
		states.NewSynRecv++
	default:
		states.Unknown++
	}
}

func collectUDPMemLimits(ctx context.Context) (UDPMemLimits, error) {
	var limits UDPMemLimits
	var errs error
	if data, err := os.ReadFile("/proc/sys/net/ipv4/udp_mem"); err == nil {
		fields := strings.Fields(strings.TrimSpace(string(data)))
		if len(fields) == 3 {
			limits.UDPMem = []uint64{parseUint(fields[0], 10), parseUint(fields[1], 10), parseUint(fields[2], 10)}
		}
	} else {
		errs = errors.Join(errs, err)
	}
	limits.UDPRMemMin = parseReadUint64("/proc/sys/net/ipv4/udp_rmem_min")
	limits.UDPWMemMin = parseReadUint64("/proc/sys/net/ipv4/udp_wmem_min")
	limits.CoreRMemDefault = parseReadUint64("/proc/sys/net/core/rmem_default")
	limits.CoreRMemMax = parseReadUint64("/proc/sys/net/core/rmem_max")
	limits.CoreWMemDefault = parseReadUint64("/proc/sys/net/core/wmem_default")
	limits.CoreWMemMax = parseReadUint64("/proc/sys/net/core/wmem_max")
	return limits, errs
}

func parseReadUint64(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return parseUint(strings.TrimSpace(string(data)), 10)
}

func collectUDPPortStats(ctx context.Context) ([]UDPPortStat, error) {
	var stats []UDPPortStat
	var errs error
	portMap4, err := parseUDPFromPath(ctx, "/proc/net/udp")
	errs = errors.Join(errs, err)
	portMap6, err := parseUDPFromPath(ctx, "/proc/net/udp6")
	errs = errors.Join(errs, err)
	portMap := mergeUDPPortMaps(portMap4, portMap6)
	for _, s := range portMap {
		stats = append(stats, *s)
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].RxQueue+stats[i].TxQueue > stats[j].RxQueue+stats[j].TxQueue
	})
	if len(stats) > topN {
		stats = stats[:topN]
	}
	return stats, errs
}

func mergeUDPPortMaps(m1, m2 map[uint16]*UDPPortStat) map[uint16]*UDPPortStat {
	result := make(map[uint16]*UDPPortStat)
	for k, v := range m1 {
		result[k] = &UDPPortStat{
			Port:    v.Port,
			Count:   v.Count,
			RxQueue: v.RxQueue,
			TxQueue: v.TxQueue,
			Drops:   v.Drops,
		}
	}
	for k, v := range m2 {
		if existing, ok := result[k]; ok {
			existing.Count += v.Count
			existing.RxQueue += v.RxQueue
			existing.TxQueue += v.TxQueue
			existing.Drops += v.Drops
		} else {
			result[k] = &UDPPortStat{
				Port:    v.Port,
				Count:   v.Count,
				RxQueue: v.RxQueue,
				TxQueue: v.TxQueue,
				Drops:   v.Drops,
			}
		}
	}
	return result
}

func parseUDPFromPath(ctx context.Context, path string) (map[uint16]*UDPPortStat, error) {
	_, f, err := scanFile(ctx, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseUDP(f)
}

func parseUDP(r io.Reader) (map[uint16]*UDPPortStat, error) {
	scanner := newScanner(r)
	portMap := make(map[uint16]*UDPPortStat)
	var header []string
	if scanner.Scan() {
		header = strings.Fields(scanner.Text())
	}
	dropsIdx := -1
	for i, h := range header {
		if strings.EqualFold(h, "drops") {
			dropsIdx = i
			break
		}
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		local := fields[1]
		parts := strings.SplitN(local, ":", 2)
		if len(parts) != 2 {
			continue
		}
		p := parseUint(parts[1], 16)
		q := strings.Split(fields[4], ":")
		if len(q) != 2 {
			continue
		}
		tx := parseUint(q[0], 16)
		rx := parseUint(q[1], 16)
		var drops uint64
		if dropsIdx >= 0 && dropsIdx < len(fields) {
			drops = parseUint(fields[dropsIdx], 10)
		}
		ps, ok := portMap[uint16(p)]
		if !ok {
			ps = &UDPPortStat{Port: uint16(p)}
			portMap[uint16(p)] = ps
		}
		ps.TxQueue += tx
		ps.RxQueue += rx
		ps.Drops += drops
		ps.Count++
	}
	return portMap, scanner.Err()
}

func collectSockStat(ctx context.Context, path string) (SockStat, error) {
	_, f, err := scanFile(ctx, path)
	if err != nil {
		return SockStat{}, err
	}
	defer f.Close()
	return parseSockStat(f)
}

func parseSockStat(r io.Reader) (SockStat, error) {
	var stat SockStat
	scanner := newScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}
		switch parts[0] {
		case "sockets:":
			if len(parts) > 2 && parts[1] == "used" {
				stat.SocketsInUse = parseUint(parts[2], 10)
			}
		case "TCP:":
			for i := 1; i < len(parts); i += 2 {
				switch parts[i] {
				case "inuse":
					stat.TCP.InUse = parseUint(parts[i+1], 10)
				case "orphan":
					stat.TCP.Orphan = parseUint(parts[i+1], 10)
				case "tw":
					stat.TCP.TW = parseUint(parts[i+1], 10)
				case "alloc":
					stat.TCP.Alloc = parseUint(parts[i+1], 10)
				case "mem":
					stat.TCP.Mem = parseUint(parts[i+1], 10)
				}
			}
		case "UDP:":
			for i := 1; i < len(parts); i += 2 {
				switch parts[i] {
				case "inuse":
					stat.UDP.InUse = parseUint(parts[i+1], 10)
				case "mem":
					stat.UDP.Mem = parseUint(parts[i+1], 10)
				}
			}
		}
	}
	return stat, scanner.Err()
}

func parseUint(s string, base int) uint64 {
	v, _ := strconv.ParseUint(s, base, 64)
	return v
}

func readUint64(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	v, perr := strconv.ParseUint(s, 10, 64)
	if perr != nil {
		return 0, fmt.Errorf("parse %s: %w", path, perr)
	}
	return v, nil
}

func readInt(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

func readTrimmedString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func scanFile(ctx context.Context, path string) (*bufio.Scanner, *os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	go func(f *os.File) {
		<-ctx.Done()
		_ = f.Close()
	}(f)
	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 256*1024) // 256 KiB
	s.Buffer(buf, 1*1024*1024)      // max 1 MiB
	return s, f, nil
}

func newScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	buf := make([]byte, 0, 256*1024) // 256 KiB
	s.Buffer(buf, 1*1024*1024)      // max 1 MiB
	return s
}
