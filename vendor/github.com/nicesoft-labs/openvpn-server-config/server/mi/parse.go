package mi

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

/*
 Предполагается, что типы:
   - Version        { OpenVPN string; Management string }
   - LoadStats      { NClients int64; BytesIn int64; BytesOut int64 }
   - Status         { Title, Time, TimeT string; ClientList []*OVClient; RoutingTable []*RoutingPath }
   - OVClient       { CommonName, RealAddress, VirtualAddress, VirtualIPv6, ConnectedSince, ConnectedSinceT, Username, ClientID, PeerID, DataCipher string; BytesReceived, BytesSent uint64; PacketsReceived, PacketsSent *uint64 (если есть) }
   - RoutingPath    { VirtualAddress, CommonName, RealAddress, LastRef, LastRefT string }
 объявлены в другом месте пакета.
*/

// ---------------------------- PID ----------------------------

// ParsePid gets pid from string
func ParsePid(input string) (int64, error) {
	a := splitLines(input)
	if len(a) != 1 {
		return 0, fmt.Errorf("Wrong number of lines, expected %d, got %d", 1, len(a))
	}
	line := strings.TrimSpace(a[0])
	if !isSuccess(line) {
		return 0, fmt.Errorf("Bad response: %s", line)
	}
	val := safeStripPrefix(line, "SUCCESS: pid=")
	return strconv.ParseInt(val, 10, 64)
}

// ------------------------- VERSION ---------------------------

// ParseVersion gets version information from string
// Принимает 2 или 3 строки.
//  1: "OpenVPN Version: OpenVPN 2.6.17 ..."
//
//  2: "Management Version: 5"
//     ИЛИ "Management Interface Version 5 -- type 'help' for more info"
//
//  3: Дополнительная строка (иногда build/SSL), игнорируется.
func ParseVersion(input string) (*Version, error) {
	v := Version{}
	a := splitLines(input)
	if len(a) < 2 || len(a) > 3 {
		return nil, fmt.Errorf("Wrong number of lines, expected 2..3, got %d", len(a))
	}

	openLine := strings.TrimSpace(a[0])
	if !strings.HasPrefix(openLine, "OpenVPN Version: ") {
		return nil, fmt.Errorf("Bad response (line 1): %s", openLine)
	}
	v.OpenVPN = strings.TrimSpace(strings.TrimPrefix(openLine, "OpenVPN Version: "))

	mgmtLine := strings.TrimSpace(a[1])
	switch {
	case strings.HasPrefix(mgmtLine, "Management Version: "):
		v.Management = strings.TrimSpace(strings.TrimPrefix(mgmtLine, "Management Version: "))
	case strings.HasPrefix(mgmtLine, "Management Interface Version "):
		// поддержка формата: "Management Interface Version 5 -- type 'help' for more info"
		rest := strings.TrimPrefix(mgmtLine, "Management Interface Version ")
		tok := strings.SplitN(rest, " ", 2)
		if len(tok) >= 1 {
			v.Management = tok[0]
		}
	default:
		return nil, fmt.Errorf("Bad response (line 2): %s", mgmtLine)
	}

	return &v, nil
}

// ------------------------- LOAD-STATS ------------------------

// ParseStats gets stats from string
// Пример: "SUCCESS: nclients=3,bytesin=...,bytesout=...,uptime=...,cpu_usage=..."
func ParseStats(input string) (*LoadStats, error) {
	ls := LoadStats{}
	a := splitLines(input)
	if len(a) != 1 {
		return nil, fmt.Errorf("Wrong number of lines, expected %d, got %d", 1, len(a))
	}
	line := strings.TrimSpace(a[0])
	if !isSuccess(line) {
		return nil, fmt.Errorf("Bad response: %s", line)
	}

	kv := strings.Split(strings.TrimPrefix(line, "SUCCESS: "), ",")
	for _, pair := range kv {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, val, ok := splitKV(pair)
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "nclients":
			if x, err := strconv.ParseInt(val, 10, 64); err == nil {
				ls.NClients = x
			}
		case "bytesin":
			if x, err := strconv.ParseInt(val, 10, 64); err == nil {
				ls.BytesIn = x
			}
		case "bytesout":
			if x, err := strconv.ParseInt(val, 10, 64); err == nil {
				ls.BytesOut = x
			}
		// Другие поля игнорируем (uptime/cpu_usage/mem_usage/…)
		}
	}
	return &ls, nil
}

// -------------------------- STATUS ---------------------------

// ParseStatus gets status information from string
// Поддерживает status 2/3. Аккуратно проверяет длину полей.
func ParseStatus(input string) (*Status, error) {
	s := Status{
		ClientList:   make([]*OVClient, 0, 8),
		RoutingTable: make([]*RoutingPath, 0, 8),
	}

	lines := splitLines(input)
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) == 0 {
			continue
		}
		tag := strings.TrimSpace(fields[0])

		switch tag {
		case "TITLE":
			if len(fields) >= 2 {
				s.Title = fields[1]
			}
		case "TIME":
			// TIME,<iso>,<epoch>
			if len(fields) >= 2 {
				s.Time = fields[1]
			}
			if len(fields) >= 3 {
				s.TimeT = fields[2]
			}
		case "ROUTING_TABLE":
			// ROUTING_TABLE,virt,cn,real,lastref,lastrefT
			if len(fields) >= 6 {
				item := &RoutingPath{
					VirtualAddress: fields[1],
					CommonName:     fields[2],
					RealAddress:    fields[3],
					LastRef:        fields[4],
					LastRefT:       fields[5],
				}
				s.RoutingTable = append(s.RoutingTable, item)
			}
		case "CLIENT_LIST":
			// Базовый формат (status 2):
			// CLIENT_LIST,cn,real,virt,virt6,bytesR,bytesS,connSince,connSinceT,username,clientID,peerID[,dataCipher][,packetsR][,packetsS][,…]
			if len(fields) >= 12 {
				bytesR, _ := strconv.ParseUint(fields[5], 10, 64)
				bytesS, _ := strconv.ParseUint(fields[6], 10, 64)
				item := &OVClient{
					CommonName:      fields[1],
					RealAddress:     fields[2],
					VirtualAddress:  fields[3],
					VirtualIPv6:     fields[4],
					BytesReceived:   bytesR,
					BytesSent:       bytesS,
					ConnectedSince:  fields[7],
					ConnectedSinceT: fields[8],
					Username:        fields[9],
					ClientID:        fields[10],
					PeerID:          fields[11],
				}
				// Необязательные поля
				if len(fields) >= 13 && fields[12] != "" {
					// DataCipher либо может быть пустым
					item.DataCipher = fields[12]
				}
				// В некоторых сборках дальше идут packetsR/packetsS
				if len(fields) >= 15 {
					if pr, err := strconv.ParseUint(fields[13], 10, 64); err == nil {
						item.PacketsReceived = &pr
					}
					if ps, err := strconv.ParseUint(fields[14], 10, 64); err == nil {
						item.PacketsSent = &ps
					}
				}
				s.ClientList = append(s.ClientList, item)
			}
		// Иные теги (GLOBAL_STATS и др.) можно добавить по мере необходимости
		}
	}
	return &s, nil
}

// ------------------------- SIGNAL/KILL -----------------------

// ParseSignal checks for error in response string
func ParseSignal(input string) error {
	a := splitLines(input)
	if len(a) != 1 {
		return fmt.Errorf("Wrong number of lines, expected %d, got %d", 1, len(a))
	}
	if !isSuccess(a[0]) {
		return fmt.Errorf("Bad response: %s", a[0])
	}
	return nil
}

// ParseKillSession gets kill command result from string
func ParseKillSession(input string) (string, error) {
	a := splitLines(input)
	if len(a) != 1 {
		return "", fmt.Errorf("Wrong number of lines, expected %d, got %d", 1, len(a))
	}
	line := strings.TrimSpace(a[0])
	if !isSuccess(line) {
		return "", errors.New(line)
	}
	return strings.TrimSpace(strings.TrimPrefix(line, "SUCCESS: ")), nil
}

// ----------------------- ДОП. ПАРСЕРЫ ------------------------

// ParseState парсит вывод `state` или `state all` в слайс строк (сырьё).
// Можно дальше разобрать на структуру при необходимости.
func ParseState(input string) ([]string, error) {
	lines := splitLines(input)
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "END") {
			continue
		}
		// строки формата: ">STATE:timestamp,STATE,detail,remote"
		if strings.HasPrefix(l, ">STATE:") || strings.HasPrefix(l, "STATE,") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		// Не критично: просто не нашли строк состояний
	}
	return out, nil
}

// ParseRemoteEntryCount парсит `remote-entry-count` → число.
func ParseRemoteEntryCount(input string) (int, error) {
	// Обычно одна строка с числом
	line := strings.TrimSpace(joinOneLine(input))
	if line == "" {
		return 0, errors.New("empty response")
	}
	// может быть "2" или "SUCCESS: 2" — покроем оба
	if isSuccess(line) {
		line = strings.TrimSpace(strings.TrimPrefix(line, "SUCCESS: "))
	}
	n, err := strconv.Atoi(line)
	if err != nil {
		return 0, fmt.Errorf("parse remote-entry-count: %w", err)
	}
	return n, nil
}

// ParseRemoteEntriesAll парсит `remote-entry-get all` → слайс строк (сырьё).
func ParseRemoteEntriesAll(input string) ([]string, error) {
	lines := splitLines(input)
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "END") {
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

// -------------------------- HELPERS --------------------------

func getLStatsValue(s string) (int64, error) {
	k, v, ok := splitKV(s)
	if !ok || k == "" {
		return -1, errors.New("Parsing error")
	}
	return strconv.ParseInt(v, 10, 64)
}

func splitKV(s string) (key, val string, ok bool) {
	a := strings.SplitN(strings.TrimSpace(s), "=", 2)
	if len(a) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(a[0]), strings.TrimSpace(a[1]), true
}

func trim(s string) string {
	return strings.Trim(strings.Trim(s, "\r\n"), "\n")
}

func splitLines(s string) []string {
	t := trim(s)
	if t == "" {
		return []string{}
	}
	return strings.Split(t, "\n")
}

func joinOneLine(s string) string {
	a := splitLines(s)
	if len(a) == 0 {
		return ""
	}
	if len(a) > 1 {
		// иногда openvpn печатает лишние переводы — склеим
		return strings.Join(a, " ")
	}
	return a[0]
}

func safeStripPrefix(s, prefix string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(s, prefix))
	}
	return s
}

func isSuccess(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "SUCCESS: ")
}
