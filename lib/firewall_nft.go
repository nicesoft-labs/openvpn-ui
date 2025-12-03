package lib

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// FirewallInfo represents nftables snapshot for UI.
type FirewallInfo struct {
	Kind          string        `json:"kind"`
	SchemaVersion int           `json:"schema_version"`
	TakenAt       string        `json:"taken_at"`
	Hostname      string        `json:"hostname"`
	Summary       FirewallStats `json:"summary"`
	Tables        []NFTTable    `json:"tables"`
	FlatRules     []NFTRule     `json:"flat_rules"`
	Warnings      []string      `json:"warnings,omitempty"`
}

// FirewallStats aggregates summary metrics.
type FirewallStats struct {
	Families      []string          `json:"families,omitempty"`
	BasePolicies  map[string]string `json:"base_policies,omitempty"`
	Totals        RuleCounters      `json:"totals"`
	ByVerdict     []VerdictAgg      `json:"by_verdict,omitempty"`
	IfaceCoverage IfaceCoverage     `json:"iface_coverage"`
	TagsAgg       []TagAgg          `json:"tags_agg,omitempty"`
}

// RuleCounters holds packet/byte counters.
type RuleCounters struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// VerdictAgg contains counters per verdict.
type VerdictAgg struct {
	Verdict string `json:"verdict"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// IfaceCoverage lists seen interfaces.
type IfaceCoverage struct {
	IIF []string `json:"iif,omitempty"`
	OIF []string `json:"oif,omitempty"`
	All []string `json:"all,omitempty"`
}

// TagAgg aggregates counters per auto tag.
type TagAgg struct {
	Tag     string `json:"tag"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// NFTTable represents nftables table.
type NFTTable struct {
	Name   string     `json:"name"`
	Family string     `json:"family"`
	Chains []NFTChain `json:"chains"`
}

// NFTChain represents nftables chain.
type NFTChain struct {
	Name        string    `json:"name"`
	Hook        string    `json:"hook"`
	Policy      string    `json:"policy"`
	PacketCount uint64    `json:"packet_count"`
	ByteCount   uint64    `json:"byte_count"`
	Rules       []NFTRule `json:"rules"`
}

// NFTRule represents nftables rule.
type NFTRule struct {
	Table   string   `json:"table"`
	Chain   string   `json:"chain"`
	Index   int      `json:"index"`
	Expr    string   `json:"expr"`
	Verdict string   `json:"verdict"`
	Matches []string `json:"matches"`
	Packets uint64   `json:"packets"`
	Bytes   uint64   `json:"bytes"`
	Tags    []string `json:"tags"`
}

// CollectFirewallInfo returns nftables snapshot.
func CollectFirewallInfo(ctx context.Context) (FirewallInfo, error) {
	info := FirewallInfo{Kind: "nftables", SchemaVersion: 1, TakenAt: time.Now().Format(time.RFC3339)}
	hostname, err := os.Hostname()
	if err == nil {
		info.Hostname = hostname
	} else {
		info.Warnings = append(info.Warnings, fmt.Sprintf("hostname: %v", err))
	}

	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		info.Warnings = append(info.Warnings, err.Error())
		return info, err
	}

	tables, err := conn.ListTables()
	if err != nil {
		info.Warnings = append(info.Warnings, fmt.Sprintf("list tables: %v", err))
		return info, err
	}

	summary := newSummaryBuilder()
	tableInfos := make([]NFTTable, 0, len(tables))
	flatRules := make([]NFTRule, 0)
	var parseWarnings []string
	hasMasq := false
	ovpnAcceptFound := false
	shadowWarnings := make([]string, 0)

	sortTables(tables)
	for _, tbl := range tables {
		tableInfo := NFTTable{Name: tableFullName(tbl), Family: familyString(tbl.Family)}
		summary.addFamily(tableInfo.Family)

		chains, err := conn.ListChainsOfTable(tbl)
		if err != nil {
			parseWarnings = append(parseWarnings, fmt.Sprintf("list chains for %s: %v", tableInfo.Name, err))
			continue
		}
		sortChains(chains)

		for _, ch := range chains {
			chainInfo := NFTChain{Name: ch.Name, Hook: hookString(ch.Hooknum), Policy: policyString(ch.Policy)}
			summary.collectBasePolicy(chainInfo.Hook, chainInfo.Policy)

			rules, err := conn.GetRule(ch.Table, ch)
			if err != nil {
				parseWarnings = append(parseWarnings, fmt.Sprintf("rules for %s/%s: %v", tableInfo.Name, ch.Name, err))
				continue
			}
			for idx, rule := range rules {
				parsed, pw := parseRule(rule)
				if len(pw) > 0 {
					parseWarnings = append(parseWarnings, pw...)
				}
				parsed.Table = tableInfo.Name
				parsed.Chain = ch.Name
				parsed.Index = idx + 1
				parsed.Expr = buildExpr(parsed.Matches, parsed.Verdict)
				chainInfo.PacketCount += parsed.Packets
				chainInfo.ByteCount += parsed.Bytes
				summary.collectRule(parsed)
				if contains(parsed.Tags, "masq") {
					hasMasq = true
				}
				if parsed.Verdict == "ACCEPT" && contains(parsed.Matches, "proto=udp") && portMatch(parsed.Matches, "dpt=") {
					ovpnAcceptFound = true
				}
				chainInfo.Rules = append(chainInfo.Rules, parsed)
				flatRules = append(flatRules, parsed)
			}
			if warn := detectShadowing(tableInfo.Name, chainInfo); warn != "" {
				shadowWarnings = append(shadowWarnings, warn)
			}
			tableInfo.Chains = append(tableInfo.Chains, chainInfo)
		}
		tableInfos = append(tableInfos, tableInfo)
	}

	info.Tables = tableInfos
	info.FlatRules = flatRules
	info.Summary = summary.finalize()

	info.Warnings = append(info.Warnings, summary.generateWarnings(ovpnAcceptFound, hasMasq)...)
	info.Warnings = append(info.Warnings, shadowWarnings...)
	info.Warnings = append(info.Warnings, parseWarnings...)

	return info, nil
}

func sortTables(tables []*nftables.Table) {
	order := map[nftables.TableFamily]int{
		nftables.TableFamilyINet: 0,
		nftables.TableFamilyIPv4: 1,
		nftables.TableFamilyIPv6: 2,
	}
	sort.Slice(tables, func(i, j int) bool {
		fi := order[tables[i].Family]
		fj := order[tables[j].Family]
		if fi == fj {
			return tables[i].Name < tables[j].Name
		}
		return fi < fj
	})
}

func sortChains(chains []*nftables.Chain) {
	hookOrder := map[uint32]int{
		nftables.ChainHookInput:       0,
		nftables.ChainHookForward:     1,
		nftables.ChainHookOutput:      2,
		nftables.ChainHookPrerouting:  3,
		nftables.ChainHookPostrouting: 4,
	}
	sort.Slice(chains, func(i, j int) bool {
		hi := 100
		if chains[i].Hooknum != nil {
			if o, ok := hookOrder[*chains[i].Hooknum]; ok {
				hi = o
			}
		}
		hj := 100
		if chains[j].Hooknum != nil {
			if o, ok := hookOrder[*chains[j].Hooknum]; ok {
				hj = o
			}
		}
		if hi == hj {
			return chains[i].Name < chains[j].Name
		}
		return hi < hj
	})
}

func familyString(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	default:
		return "unknown"
	}
}

func tableFullName(t *nftables.Table) string {
	fam := familyString(t.Family)
	if fam == "inet" {
		return fmt.Sprintf("%s %s", fam, t.Name)
	}
	return t.Name
}

func hookString(h *uint32) string {
	if h == nil {
		return ""
	}
	switch *h {
	case nftables.ChainHookInput:
		return "input"
	case nftables.ChainHookForward:
		return "forward"
	case nftables.ChainHookOutput:
		return "output"
	case nftables.ChainHookPrerouting:
		return "prerouting"
	case nftables.ChainHookPostrouting:
		return "postrouting"
	default:
		return ""
	}
}

func policyString(policy *nftables.ChainPolicy) string {
	if policy == nil {
		return ""
	}
	switch *policy {
	case nftables.ChainPolicyAccept:
		return "ACCEPT"
	case nftables.ChainPolicyDrop:
		return "DROP"
	default:
		return ""
	}
}

type ruleParseResult struct {
	matches []string
	verdict string
	packets uint64
	bytes   uint64
	tags    []string
}

func parseRule(r *nftables.Rule) (NFTRule, []string) {
	res := NFTRule{}
	warnings := make([]string, 0)
	matchSet := make(map[string]struct{})
	tagSet := make(map[string]struct{})

	for i := 0; i < len(r.Exprs); i++ {
		exprAny := r.Exprs[i]
		switch e := exprAny.(type) {
		case *expr.Counter:
			res.Packets += e.Packets
			res.Bytes += e.Bytes
		case *expr.Verdict:
			res.Verdict = verdictString(e)
		case *expr.Meta:
			if i+1 < len(r.Exprs) {
				if cmp, ok := r.Exprs[i+1].(*expr.Cmp); ok && cmp.Register == e.Register {
					if m, ok := parseMetaMatch(e, cmp); ok {
						matchSet[m] = struct{}{}
					}
					i++
				}
			}
		case *expr.Payload:
			if i+1 < len(r.Exprs) {
				if cmp, ok := r.Exprs[i+1].(*expr.Cmp); ok && cmp.Register == e.Register {
					if m, ok := parsePayloadMatch(e, cmp); ok {
						matchSet[m] = struct{}{}
					}
					i++
				}
			}
		case *expr.Ct:
			if e.Key == expr.CtKeySTATE && i+1 < len(r.Exprs) {
				if cmp, ok := r.Exprs[i+1].(*expr.Cmp); ok && cmp.Register == e.Register {
					stateMatch := formatCtStates(cmp.Data)
					matchSet[stateMatch] = struct{}{}
					if strings.Contains(stateMatch, "ESTABLISHED") || strings.Contains(stateMatch, "RELATED") {
						tagSet["established"] = struct{}{}
					}
					i++
				}
			}
		case *expr.Masq:
			tagSet["masq"] = struct{}{}
		case *expr.Redir:
			tagSet["redir"] = struct{}{}
		}
	}

	res.Matches = setToSortedSlice(matchSet)
	res.Tags = setToSortedSlice(tagSet)
	res.Expr = buildExpr(res.Matches, res.Verdict)

	if hasTunTag(res.Matches) {
		addTag(&res, "tun")
	}
	if hasOpenVPNTag(res.Matches) {
		addTag(&res, "ovpn-udp")
	}

	return res, warnings
}

func verdictString(v *expr.Verdict) string {
	switch v.Kind {
	case expr.VerdictAccept:
		return "ACCEPT"
	case expr.VerdictDrop:
		return "DROP"
	case expr.VerdictReturn:
		return "RETURN"
	case expr.VerdictJump:
		return "JUMP"
	case expr.VerdictMasq:
		return "MASQUERADE"
	case expr.VerdictRedirect:
		return "REDIRECT"
	default:
		if v.Chain != "" {
			return "JUMP"
		}
		return ""
	}
}

func parseMetaMatch(m *expr.Meta, cmp *expr.Cmp) (string, bool) {
	value := strings.TrimRight(string(cmp.Data), "\x00")
	switch m.Key {
	case expr.MetaKeyIIFNAME:
		return fmt.Sprintf("iif=%s", value), true
	case expr.MetaKeyOIFNAME:
		return fmt.Sprintf("oif=%s", value), true
	case expr.MetaKeyL4PROTO:
		proto := ""
		if len(cmp.Data) > 0 {
			switch cmp.Data[0] {
			case 0x11:
				proto = "udp"
			case 0x06:
				proto = "tcp"
			default:
				proto = fmt.Sprintf("0x%x", cmp.Data[0])
			}
		}
		if proto != "" {
			return fmt.Sprintf("proto=%s", proto), true
		}
	}
	return "", false
}

func parsePayloadMatch(p *expr.Payload, cmp *expr.Cmp) (string, bool) {
	if p.Base != expr.PayloadBaseTransport || p.Len != 2 {
		return "", false
	}
	if len(cmp.Data) < 2 {
		return "", false
	}
	port := binary.BigEndian.Uint16(cmp.Data[:2])
	switch p.Offset {
	case 0:
		return fmt.Sprintf("spt=%d", port), true
	case 2:
		return fmt.Sprintf("dpt=%d", port), true
	}
	return "", false
}

func formatCtStates(data []byte) string {
	if len(data) < 4 {
		return fmt.Sprintf("ct=0x%x", data)
	}
	mask := binary.LittleEndian.Uint32(data)
	parts := make([]string, 0)
	stateMap := []struct {
		bit  uint32
		name string
	}{
		{1 << 0, "NEW"},
		{1 << 1, "ESTABLISHED"},
		{1 << 2, "RELATED"},
		{1 << 3, "INVALID"},
		{1 << 4, "UNTRACKED"},
		{1 << 5, "SNAT"},
		{1 << 6, "DNAT"},
	}
	for _, st := range stateMap {
		if mask&st.bit != 0 {
			parts = append(parts, st.name)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("ct=0x%x", data)
	}
	sort.Strings(parts)
	return "ct=" + strings.Join(parts, "|")
}

func setToSortedSlice(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	res := make([]string, 0, len(set))
	for v := range set {
		res = append(res, v)
	}
	sort.Strings(res)
	return res
}

func buildExpr(matches []string, verdict string) string {
	parts := append([]string{}, matches...)
	sort.Strings(parts)
	expr := strings.Join(parts, " ")
	if verdict != "" {
		if expr != "" {
			expr += " -> "
		}
		expr += verdict
	}
	return expr
}

func addTag(rule *NFTRule, tag string) {
	if !contains(rule.Tags, tag) {
		rule.Tags = append(rule.Tags, tag)
		sort.Strings(rule.Tags)
	}
}

func hasTunTag(matches []string) bool {
	for _, m := range matches {
		if strings.HasPrefix(m, "iif=") || strings.HasPrefix(m, "oif=") {
			val := strings.SplitN(m, "=", 2)[1]
			if strings.HasPrefix(val, "tun") || strings.HasPrefix(val, "tap") || strings.HasPrefix(val, "wg") {
				return true
			}
		}
	}
	return false
}

func hasOpenVPNTag(matches []string) bool {
	hasProto := false
	hasPort := false
	for _, m := range matches {
		if m == "proto=udp" {
			hasProto = true
		}
		if strings.HasPrefix(m, "dpt=") {
			hasPort = true
		}
	}
	return hasProto && hasPort
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func portMatch(matches []string, prefix string) bool {
	for _, m := range matches {
		if strings.HasPrefix(m, prefix) {
			return true
		}
	}
	return false
}

// summaryBuilder accumulates aggregates.
type summaryBuilder struct {
	families     map[string]struct{}
	basePolicies map[string]string
	totals       RuleCounters
	verdicts     map[string]RuleCounters
	ifaceIIF     map[string]struct{}
	ifaceOIF     map[string]struct{}
	tagAgg       map[string]RuleCounters
}

func newSummaryBuilder() *summaryBuilder {
	return &summaryBuilder{
		families:     make(map[string]struct{}),
		basePolicies: make(map[string]string),
		verdicts:     make(map[string]RuleCounters),
		ifaceIIF:     make(map[string]struct{}),
		ifaceOIF:     make(map[string]struct{}),
		tagAgg:       make(map[string]RuleCounters),
	}
}

func (s *summaryBuilder) addFamily(fam string) {
	if fam != "" {
		s.families[fam] = struct{}{}
	}
}

func (s *summaryBuilder) collectBasePolicy(hook, policy string) {
	if policy == "" || hook == "" {
		return
	}
	if hook == "input" || hook == "forward" || hook == "output" {
		if _, ok := s.basePolicies[hook]; !ok {
			s.basePolicies[hook] = policy
		}
	}
}

func (s *summaryBuilder) collectRule(rule NFTRule) {
	s.totals.Packets += rule.Packets
	s.totals.Bytes += rule.Bytes
	if rule.Verdict != "" {
		c := s.verdicts[rule.Verdict]
		c.Packets += rule.Packets
		c.Bytes += rule.Bytes
		s.verdicts[rule.Verdict] = c
	}
	for _, m := range rule.Matches {
		if strings.HasPrefix(m, "iif=") {
			s.ifaceIIF[strings.TrimPrefix(m, "iif=")] = struct{}{}
		}
		if strings.HasPrefix(m, "oif=") {
			s.ifaceOIF[strings.TrimPrefix(m, "oif=")] = struct{}{}
		}
	}
	for _, tag := range rule.Tags {
		c := s.tagAgg[tag]
		c.Packets += rule.Packets
		c.Bytes += rule.Bytes
		s.tagAgg[tag] = c
	}
}

func (s *summaryBuilder) finalize() FirewallStats {
	stats := FirewallStats{
		Families:     sortedKeys(s.families, []string{"inet", "ip", "ip6"}),
		BasePolicies: s.basePolicies,
		Totals:       s.totals,
		IfaceCoverage: IfaceCoverage{
			IIF: sortedKeys(s.ifaceIIF, nil),
			OIF: sortedKeys(s.ifaceOIF, nil),
		},
	}
	stats.IfaceCoverage.All = mergeSorted(stats.IfaceCoverage.IIF, stats.IfaceCoverage.OIF)

	verdicts := []string{"ACCEPT", "DROP", "RETURN", "JUMP", "MASQUERADE", "REDIRECT"}
	for _, v := range verdicts {
		if agg, ok := s.verdicts[v]; ok {
			stats.ByVerdict = append(stats.ByVerdict, VerdictAgg{Verdict: v, Packets: agg.Packets, Bytes: agg.Bytes})
		}
	}

	for tag, agg := range s.tagAgg {
		stats.TagsAgg = append(stats.TagsAgg, TagAgg{Tag: tag, Packets: agg.Packets, Bytes: agg.Bytes})
	}
	sort.Slice(stats.TagsAgg, func(i, j int) bool { return stats.TagsAgg[i].Tag < stats.TagsAgg[j].Tag })
	return stats
}

func (s *summaryBuilder) generateWarnings(ovpnAcceptFound, hasMasq bool) []string {
	warnings := make([]string, 0)
	if !ovpnAcceptFound {
		warnings = append(warnings, "Не найдено ACCEPT для udp/1194 (INPUT/prerouting)")
	}
	if !s.hasEarlyEstablishedAccept() {
		warnings = append(warnings, "Нет early-ACCEPT ESTABLISHED,RELATED в base-цепях")
	}
	if !hasMasq {
		warnings = append(warnings, "Не обнаружен MASQUERADE (NAT) — возможно, трафик из туннеля не выходит")
	}
	return warnings
}

func (s *summaryBuilder) hasEarlyEstablishedAccept() bool {
	if _, ok := s.tagAgg["established"]; ok {
		return true
	}
	return false
}

func sortedKeys(m map[string]struct{}, priority []string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	used := make(map[string]bool)
	for _, p := range priority {
		if _, ok := m[p]; ok {
			keys = append(keys, p)
			used[p] = true
		}
	}
	rest := make([]string, 0, len(m)-len(keys))
	for k := range m {
		if used[k] {
			continue
		}
		rest = append(rest, k)
	}
	sort.Strings(rest)
	return append(keys, rest...)
}

func mergeSorted(a, b []string) []string {
	set := make(map[string]struct{})
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		set[v] = struct{}{}
	}
	return sortedKeys(set, nil)
}

func detectShadowing(table string, chain NFTChain) string {
	broadDropSeen := false
	for _, rule := range chain.Rules {
		if rule.Verdict == "DROP" && len(rule.Matches) == 0 {
			broadDropSeen = true
			continue
		}
		if broadDropSeen && rule.Verdict == "ACCEPT" && len(rule.Matches) > 0 {
			return fmt.Sprintf("Возможен shadowing: широкое DROP выше, чем более специфичный ACCEPT (%s/%s)", table, chain.Name)
		}
	}
	return ""
}

// Helper to identify fatal permission errors for handler.
func IsFirewallPermissionError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}
