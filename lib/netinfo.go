package lib

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/beego/beego/v2/core/logs"
)

// NetInfo aggregates network telemetry snapshot.
type NetInfo struct {
	Ifaces    []NetInterface `json:"ifaces,omitempty"`
	Softnet   SoftnetStat    `json:"softnet,omitempty"`
	SNMP      SNMPStats      `json:"snmp,omitempty"`
	Conntrack ConntrackStat  `json:"conntrack,omitempty"`
	TCPStates TCPStates      `json:"tcp_states,omitempty"`
}

// NetInterface represents counters and metadata for a network interface.
type NetInterface struct {
	Name            string  `json:"name"`
	MAC             string  `json:"mac,omitempty"`
	MTU             *int    `json:"mtu,omitempty"`
	OperState       string  `json:"operstate,omitempty"`
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
	TCP    map[string]uint64 `json:"tcp,omitempty"`
	UDP    map[string]uint64 `json:"udp,omitempty"`
	TCPExt map[string]uint64 `json:"tcpext,omitempty"`
}

// ConntrackStat holds conntrack counters.
type ConntrackStat struct {
	Count   *uint64 `json:"count,omitempty"`
	Max     *uint64 `json:"max,omitempty"`
	Buckets *uint64 `json:"buckets,omitempty"`
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
}

// CollectNetInfo gathers network metrics snapshot.
func CollectNetInfo() (NetInfo, error) {
	netinfo := NetInfo{}
	defer func() {
		if r := recover(); r != nil {
			logs.Warn(fmt.Sprintf("netinfo collection panic: %v", r))
		}
	}()
	netinfo.Ifaces = collectInterfaces()
	netinfo.Softnet = collectSoftnet()
	netinfo.SNMP = collectSNMP()
	netinfo.Conntrack = collectConntrack()
	netinfo.TCPStates = collectTCPStates()
	return netinfo, nil
}

func collectInterfaces() []NetInterface {
	fallback := parseProcNetDev()
	names := listInterfaces(fallback)
	result := make([]NetInterface, 0, len(names))
	for _, name := range names {
		iface := NetInterface{Name: name}
		basePath := filepath.Join("/sys/class/net", name)
		if mac, err := readTrimmedString(filepath.Join(basePath, "address")); err == nil {
			iface.MAC = mac
		}
		if mtu, err := readInt(filepath.Join(basePath, "mtu")); err == nil {
			m := int(mtu)
			iface.MTU = &m
		}
		if oper, err := readTrimmedString(filepath.Join(basePath, "operstate")); err == nil {
			iface.OperState = oper
		}
		if speed, err := readInt(filepath.Join(basePath, "speed")); err == nil {
			// Drivers often return -1 if speed is unknown
			if speed >= 0 {
				s := int64(speed)
				iface.SpeedMbps = &s
			}
		}
		if duplex, err := readTrimmedString(filepath.Join(basePath, "duplex")); err == nil {
			iface.Duplex = duplex
		}
		if qdisc, err := readTrimmedString(filepath.Join(basePath, "qdisc")); err == nil {
			iface.QDisc = qdisc
		}
		setCounter := func(path string) *uint64 {
			if v, err := readUint64(path); err == nil {
				val := v
				return &val
			}
			return nil
		}
		iface.RxBytes = setCounter(filepath.Join(basePath, "statistics/rx_bytes"))
		iface.TxBytes = setCounter(filepath.Join(basePath, "statistics/tx_bytes"))
		iface.RxPackets = setCounter(filepath.Join(basePath, "statistics/rx_packets"))
		iface.TxPackets = setCounter(filepath.Join(basePath, "statistics/tx_packets"))
		iface.RxErrors = setCounter(filepath.Join(basePath, "statistics/rx_errors"))
		iface.TxErrors = setCounter(filepath.Join(basePath, "statistics/tx_errors"))
		iface.RxDropped = setCounter(filepath.Join(basePath, "statistics/rx_dropped"))
		iface.TxDropped = setCounter(filepath.Join(basePath, "statistics/tx_dropped"))
		iface.RxFifoErrors = setCounter(filepath.Join(basePath, "statistics/rx_fifo_errors"))
		iface.TxFifoErrors = setCounter(filepath.Join(basePath, "statistics/tx_fifo_errors"))
		iface.RxFrameErrors = setCounter(filepath.Join(basePath, "statistics/rx_frame_errors"))
		iface.TxCarrierErrors = setCounter(filepath.Join(basePath, "statistics/tx_carrier_errors"))
		iface.Multicast = setCounter(filepath.Join(basePath, "statistics/multicast"))
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
	return result
}

func listInterfaces(fallback map[string]procNetDevStat) []string {
	entries, err := os.ReadDir("/sys/class/net")
	allowedPrefix := []string{"eth", "en", "tun", "tap", "wg"}
	matches := func(name string) bool {
		for _, p := range allowedPrefix {
			if strings.HasPrefix(name, p) {
				return true
			}
		}
		return false
	}
	names := make([]string, 0, len(entries))
	if err == nil {
		for _, e := range entries {
			name := e.Name()
			if name == "lo" {
				continue
			}
			if matches(name) {
				names = append(names, name)
			}
		}
	} else {
		logs.Warn(fmt.Sprintf("cannot read /sys/class/net: %v", err))
	}
	if len(names) == 0 && len(fallback) > 0 {
		for name := range fallback {
			if name == "lo" {
				continue
			}
			if matches(name) {
				names = append(names, name)
			}
		}
	}
	return names
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

func parseProcNetDev() map[string]procNetDevStat {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		logs.Debug(fmt.Sprintf("cannot open /proc/net/dev: %v", err))
		return map[string]procNetDevStat{}
	}
	defer file.Close()
	stats := make(map[string]procNetDevStat)
	scanner := bufio.NewScanner(file)
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
		vals := make([]uint64, 0, 16)
		for _, p := range parts[1:] {
			if v, err := strconv.ParseUint(p, 10, 64); err == nil {
				vals = append(vals, v)
			} else {
				vals = append(vals, 0)
			}
		}
		if len(vals) < 16 {
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
	if err := scanner.Err(); err != nil {
		logs.Debug(fmt.Sprintf("error reading /proc/net/dev: %v", err))
	}
	return stats
}

func collectSoftnet() SoftnetStat {
	file, err := os.Open("/proc/net/softnet_stat")
	if err != nil {
		logs.Debug(fmt.Sprintf("cannot open /proc/net/softnet_stat: %v", err))
		return SoftnetStat{}
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	perCPU := make([]SoftnetCPU, 0, 4)
	totals := SoftnetTotal{}
	idx := 0
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			idx++
			continue
		}
		cpuStat := SoftnetCPU{CPU: idx}
		cpuStat.Processed = parseHexField(fields, 0)
		cpuStat.Dropped = parseHexField(fields, 1)
		cpuStat.TimeSqueezed = parseHexField(fields, 2)
		if len(fields) > 9 {
			cpuStat.FlowLimitCount = parseHexField(fields, 9)
		}
		perCPU = append(perCPU, cpuStat)
		totals.Processed += cpuStat.Processed
		totals.Dropped += cpuStat.Dropped
		totals.TimeSqueezed += cpuStat.TimeSqueezed
		totals.FlowLimitCount += cpuStat.FlowLimitCount
		idx++
	}
	if err := scanner.Err(); err != nil {
		logs.Debug(fmt.Sprintf("error reading /proc/net/softnet_stat: %v", err))
	}
	return SoftnetStat{PerCPU: perCPU, Total: totals}
}

func parseHexField(fields []string, idx int) uint64 {
	if idx >= len(fields) {
		return 0
	}
	v, err := strconv.ParseUint(fields[idx], 16, 64)
	if err != nil {
		return 0
	}
	return v
}

func collectSNMP() SNMPStats {
	stats := SNMPStats{}
	stats.TCP = extractSnmpSection("/proc/net/snmp", "Tcp")
	stats.UDP = extractSnmpSection("/proc/net/snmp", "Udp")
	// Different cases for TcpExt section may be encountered
	tcpext := extractSnmpSection("/proc/net/netstat", "TcpExt")
	if len(tcpext) == 0 {
		tcpext = extractSnmpSection("/proc/net/netstat", "TCPExt")
	}
	if len(tcpext) == 0 {
		tcpext = extractSnmpSection("/proc/net/netstat", "Tcpext")
	}
	stats.TCPExt = tcpext
	return stats
}

func extractSnmpSection(path, section string) map[string]uint64 {
	file, err := os.Open(path)
	if err != nil {
		logs.Debug(fmt.Sprintf("cannot open %s: %v", path, err))
		return nil
	}
	defer file.Close()
	return parseSnmpSection(file, section)
}

func parseSnmpSection(r io.Reader, section string) map[string]uint64 {
	scanner := bufio.NewScanner(r)
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
			if v, err := strconv.ParseUint(values[i], 10, 64); err == nil {
				out[key] = v
			}
		}
		// Do not exit early — take the last section occurrence as the most recent
		last = out
	}
	if err := scanner.Err(); err != nil {
		logs.Debug(fmt.Sprintf("error reading snmp section %s: %v", section, err))
	}
	return last
}

func collectConntrack() ConntrackStat {
	stat := ConntrackStat{}
	if v, err := readUint64("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		val := v
		stat.Count = &val
	}
	if v, err := readUint64("/proc/sys/net/netfilter/nf_conntrack_max"); err == nil {
		val := v
		stat.Max = &val
	}
	if v, err := readUint64("/proc/sys/net/netfilter/nf_conntrack_buckets"); err == nil {
		val := v
		stat.Buckets = &val
	}
	return stat
}

func collectTCPStates() TCPStates {
	states := TCPStates{}
	parseTCPFile := func(path string) {
		file, err := os.Open(path)
		if err != nil {
			logs.Debug(fmt.Sprintf("cannot open %s: %v", path, err))
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			if lineNum == 1 {
				continue
			}
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			stateHex := fields[3]
			incrementTCPState(&states, stateHex)
		}
		if err := scanner.Err(); err != nil {
			logs.Debug(fmt.Sprintf("error reading %s: %v", path, err))
		}
	}
	parseTCPFile("/proc/net/tcp")
	parseTCPFile("/proc/net/tcp6")
	return states
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

func readUint64(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	return strconv.ParseUint(s, 10, 64)
}

func readInt(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	return strconv.ParseInt(s, 10, 64)
}

func readTrimmedString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
