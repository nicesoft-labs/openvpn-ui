package lib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
)

const (
	TagMasq        = "masq"
	TagRedir       = "redir"
	TagEstablished = "established"
	TagTun         = "tun"
	TagVpnPort     = "vpn-port"
	TagFlowOffload = "flowoffload"

	DefaultWarnShadowing = true
	DefaultWarnNoNat     = true

	ChainCountersModeSumOfRules = "sum_of_rules"

	MaxWarningsPerCategory = 50
	MaxUnhandledTypes      = 10
	MaxFlatRules           = 1000
	MaxSetPreview          = 5

	MTUThreshold = 100

	SchemaVersion = 2

	ProducerName    = "nft-snapshot"
	ProducerVersion = "1.0.0"
	ProducerAPI     = "NiceVPN"
)

var (
	MTUAllowedDeltas = []int{8, 20, 28, 80} // PPPoE, L2TP, GRE, WG
)

// VPNPort represents a protocol and port pair for VPN.
type VPNPort struct {
	Proto string `json:"proto"`
	Port  uint16 `json:"port"`
}

// Config holds configuration switches for CollectFirewallInfo.
type Config struct {
	ExpectedVPNPorts []VPNPort `json:"expected_vpn_ports"`
	DeploymentRole   string    `json:"deployment_role"` // vpn_gateway_nat|vpn_gateway_routed|vpn_client_only
	WarnShadowing    *bool     `json:"warn_shadowing"`
	WarnNoNat        *bool     `json:"warn_no_nat"`
}

// ApplyDefaults applies default values to config if not set.
func ApplyDefaults(cfg *Config) {
	if cfg.WarnShadowing == nil {
		b := DefaultWarnShadowing
		cfg.WarnShadowing = &b
	}
	if cfg.WarnNoNat == nil {
		b := DefaultWarnNoNat
		cfg.WarnNoNat = &b
	}
	if len(cfg.ExpectedVPNPorts) == 0 {
		cfg.ExpectedVPNPorts = []VPNPort{{"udp", 1194}, {"tcp", 443}}
	}
}

// summaryBuilder aggregates counters while parsing rules.
type summaryBuilder struct {
	families     map[string]struct{}
	basePolicies map[string]string
	verdicts     map[string]RuleCounters
	totals       RuleCounters

	iif     map[string]struct{}
	oif     map[string]struct{}
	tagsAgg map[string]RuleCounters
}

func newSummaryBuilder() *summaryBuilder {
	return &summaryBuilder{
		families:     make(map[string]struct{}),
		basePolicies: make(map[string]string),
		verdicts:     make(map[string]RuleCounters),
		iif:          make(map[string]struct{}),
		oif:          make(map[string]struct{}),
		tagsAgg:      make(map[string]RuleCounters),
	}
}

func (s *summaryBuilder) addFamily(family string) {
	if family == "" {
		return
	}
	s.families[family] = struct{}{}
}

func (s *summaryBuilder) collectRule(rule NFTRule) {
	// Общие тоталы по всем правилам
	s.totals.Packets += rule.Packets
	s.totals.Bytes += rule.Bytes

	// Агрегация по вердикту
	if rule.Verdict != "" {
		agg := s.verdicts[rule.Verdict]
		agg.Packets += rule.Packets
		agg.Bytes += rule.Bytes
		s.verdicts[rule.Verdict] = agg
	}

	// Покрытие интерфейсов
	if rule.InIface != "" {
		s.iif[rule.InIface] = struct{}{}
	}
	if rule.OutIface != "" {
		s.oif[rule.OutIface] = struct{}{}
	}

	// Агрегация по тегам
	for _, t := range rule.Tags {
		agg := s.tagsAgg[t]
		agg.Packets += rule.Packets
		agg.Bytes += rule.Bytes
		s.tagsAgg[t] = agg
	}
}

// FirewallInfo represents nftables snapshot for UI.
type FirewallInfo struct {
	Kind                   string              `json:"kind"`
	SchemaVersion          int                 `json:"schema_version"`
	TakenAt                string              `json:"taken_at"`
	Hostname               string              `json:"hostname"`
	Summary                FirewallStats       `json:"summary"`
	Tables                 []NFTTable          `json:"tables"`
	FlatRules              []NFTRule           `json:"flat_rules"`
	Sets                   []NFTSet            `json:"sets,omitempty"`
	Maps                   []NFTMap            `json:"maps,omitempty"`
	Flowtables             []NFTFlowtable      `json:"flowtables,omitempty"`
	Warnings               map[string][]string `json:"warnings,omitempty"`
	HasDefaultRoute        bool                `json:"has_default_route"`
	UplinkIfaces           []string            `json:"uplink_ifaces,omitempty"`
	MTUMismatchDetected    bool                `json:"mtu_mismatch_detected"`
	ChainCountersMode      string              `json:"chain_counters_mode"`
	PartialMode            bool                `json:"partial_mode,omitempty"`
	HasEstablishedFastpath bool                `json:"has_established_fastpath"`
	HasForwardPolicyAccept bool                `json:"has_forward_policy_accept"`
	HasForwardPolicyDrop   bool                `json:"has_forward_policy_drop"`
	Counts                 map[string]int      `json:"counts,omitempty"` // rules_total, rules_shown, chains_total, tables_total, sets_total, etc.
	Producer               ProducerInfo        `json:"producer"`
}

// ProducerInfo holds producer metadata.
type ProducerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	API     string `json:"api"`
}

// FirewallStats aggregates summary metrics.
type FirewallStats struct {
	Families      []string          `json:"families,omitempty"`
	BasePolicies  map[string]string `json:"base_policies,omitempty"`
	Totals        RuleCounters      `json:"totals"`
	ByVerdict     []VerdictAgg      `json:"by_verdict,omitempty"`
	IfaceCoverage IfaceCoverage     `json:"iface_coverage"`
	TagsAgg       []TagAgg          `json:"tags_agg,omitempty"`
	Meta          StatsMeta         `json:"meta,omitempty"`
}

// StatsMeta holds metadata for stats.
type StatsMeta struct {
	CountersMode string     `json:"counters_mode,omitempty"`
	FallbackMode bool       `json:"fallback_mode,omitempty"`
	APILevel     string     `json:"api_level,omitempty"`
	Note         string     `json:"note,omitempty"`
	Confidence   Confidence `json:"confidence,omitempty"`
}

// Confidence holds confidence levels.
type Confidence struct {
	Counters string `json:"counters"` // high|low
	Objects  string `json:"objects"`  // high|partial
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
	Orphan      bool      `json:"orphan,omitempty"`
}

// NFTRule represents nftables rule.
type NFTRule struct {
	Table       string   `json:"table"`
	Chain       string   `json:"chain"`
	Index       int      `json:"index"`
	Expr        string   `json:"expr"`
	Verdict     string   `json:"verdict"`
	JumpTarget  string   `json:"jump_target,omitempty"`
	Matches     []string `json:"matches"`
	Packets     uint64   `json:"packets"`
	Bytes       uint64   `json:"bytes"`
	Tags        []string `json:"tags"`
	Fingerprint string   `json:"fingerprint"`

	// Для UI в стиле iptables и графиков
	Proto    string  `json:"proto,omitempty"`     // tcp/udp/…
	Src      string  `json:"src,omitempty"`       // source address
	Dst      string  `json:"dst,omitempty"`       // destination address
	Sport    *uint16 `json:"sport,omitempty"`     // source port
	Dport    *uint16 `json:"dport,omitempty"`     // destination port
	InIface  string  `json:"in_iface,omitempty"`  // iifname
	OutIface string  `json:"out_iface,omitempty"` // oifname
}

// NFTSet represents nftables set.
type NFTSet struct {
	Name     string   `json:"name"`
	Family   string   `json:"family"`
	Table    string   `json:"table"`
	Type     string   `json:"type"`
	KeyType  string   `json:"key_type,omitempty"`
	Elements int      `json:"elements"`
	Preview  []string `json:"preview,omitempty"`
	Orphan   bool     `json:"orphan,omitempty"`
}

// NFTMap represents nftables map.
type NFTMap struct {
	Name     string `json:"name"`
	Family   string `json:"family"`
	Table    string `json:"table"`
	Type     string `json:"type"`
	KeyType  string `json:"key_type,omitempty"`
	MapType  string `json:"map_type,omitempty"`
	Elements int    `json:"elements"`
	Orphan   bool   `json:"orphan,omitempty"`
}

// NFTFlowtable represents nftables flowtable.
type NFTFlowtable struct {
	Name   string `json:"name"`
	Family string `json:"family"`
	Table  string `json:"table"`
	Orphan bool   `json:"orphan,omitempty"`
}

// CollectFirewallInfo returns nftables snapshot.
func CollectFirewallInfo(ctx context.Context, cfg Config) (FirewallInfo, error) {
	ApplyDefaults(&cfg)

	info := FirewallInfo{
		Kind:              "nftables",
		SchemaVersion:     SchemaVersion,
		TakenAt:           time.Now().Format(time.RFC3339),
		Warnings:          make(map[string][]string),
		ChainCountersMode: ChainCountersModeSumOfRules,
		Summary: FirewallStats{
			Meta: StatsMeta{
				CountersMode: "sum of rule counters, not kernel chain counters",
				Note:         "Chain counters are sum of rules; kernel chain counters not read",
				Confidence: Confidence{
					Counters: "high",
					Objects:  "high",
				},
			},
		},
		Counts: make(map[string]int),
		Producer: ProducerInfo{
			Name:    ProducerName,
			Version: ProducerVersion,
			API:     ProducerAPI,
		},
	}

	hostname, err := os.Hostname()
	if err != nil {
		addWarning(&info, "parser", fmt.Sprintf("hostname: %v", err))
	} else {
		info.Hostname = hostname
	}

	conn, err := nftables.New(nftables.AsLasting())
	partial := false
	if err != nil {
		addWarning(&info, "permissions", fmt.Sprintf("nftables conn: %v (no CAP_NET_ADMIN?)", err))
		partialInfo, partialErr := fallbackCollectViaNftJSON(ctx)
		if partialErr == nil {
			info.Tables = partialInfo.Tables
			info.FlatRules = partialInfo.FlatRules
			info.Sets = partialInfo.Sets
			partial = true
			info.PartialMode = true
			info.Summary.Meta.FallbackMode = true
			info.Summary.Meta.APILevel = "partial"
			info.Summary.Meta.Confidence.Counters = "low"
			info.Summary.Meta.Confidence.Objects = "partial"
			info.Summary.Meta.Note += "; Counters unavailable in partial mode"
		} else {
			addWarning(&info, "permissions", fmt.Sprintf("fallback failed: %v", partialErr))
			return info, err
		}
	} else {
		defer conn.CloseLasting()
		info.Summary.Meta.APILevel = "full"
	}

	summary := newSummaryBuilder()
	tableInfos := make([]NFTTable, 0)
	flatRules := make([]NFTRule, 0)
	hasMasq := false
	vpnAcceptFound := make(map[string]bool)
	vpnUnknownCoverage := make(map[string]struct{})
	missingVPN := make([]string, 0)
	for _, vp := range cfg.ExpectedVPNPorts {
		key := fmt.Sprintf("%s_%d", vp.Proto, vp.Port)
		vpnAcceptFound[key] = false
	}

	chainUsage := make(map[string]bool)
	setUsage := make(map[string]bool)
	mapUsage := make(map[string]bool)

	unhandledTypes := make(map[string]bool)
	setPreviews := make(map[string][]string) // "table:set" -> preview

	if partial {
		for _, tbl := range info.Tables {
			info.Counts["tables_total"]++
			summary.addFamily(tbl.Family)
			for _, ch := range tbl.Chains {
				key := fmt.Sprintf("%s_%s", tbl.Family, ch.Hook)
				summary.collectBasePolicy(key, ch.Policy)
				info.Counts["chains_total"]++
				info.Counts["rules_total"] += len(ch.Rules)
				for _, rule := range ch.Rules {
					summary.collectRule(rule)
					if len(flatRules) < MaxFlatRules {
						flatRules = append(flatRules, rule)
					}
				}
			}
		}
		info.Summary = summary.finalize()
		info.FlatRules = flatRules
		info.Counts["rules_shown"] = len(flatRules)
		if info.Counts["rules_total"] > MaxFlatRules {
			addWarning(&info, "parser", fmt.Sprintf("Flat rules truncated to %d; shown %d of %d total", MaxFlatRules, info.Counts["rules_shown"], info.Counts["rules_total"]))
		}
	} else {
		tables, err := conn.ListTables()
		if err != nil {
			addWarning(&info, "parser", fmt.Sprintf("list tables: %v", err))
			return info, err
		}

		sortTables(tables)
		for _, tbl := range tables {
			tableName := tableFullName(tbl)
			family := familyString(tbl.Family)
			summary.addFamily(family)

			chains, err := listChainsOfTable(conn, tbl)
			if err != nil {
				addWarning(&info, "parser", fmt.Sprintf("list chains for %s: %v", tableName, err))
				continue
			}

			tableInfo := NFTTable{Name: tableName, Family: family}

			sortChains(chains)
			for _, ch := range chains {
				hook := hookString(ch.Hooknum)
				policy := policyString(ch.Policy)
				chainInfo := NFTChain{Name: ch.Name, Hook: hook, Policy: policy}
				key := fmt.Sprintf("%s_%s", family, chainInfo.Hook)
				summary.collectBasePolicy(key, chainInfo.Policy)

				if chainInfo.Hook == "forward" {
					if chainInfo.Policy == "ACCEPT" {
						info.HasForwardPolicyAccept = true
					} else if chainInfo.Policy == "DROP" {
						info.HasForwardPolicyDrop = true
					}
				}

				rules, err := conn.GetRule(tbl, ch)
				if err != nil {
					addWarning(&info, "parser", fmt.Sprintf("rules for %s/%s: %v", tableName, ch.Name, err))
					continue
				}

				hasAccept := false
				broadDropSeen := false
				shadowWarned := false
				establishedSeen := false
				narrowMatchSeen := false
				chainHasFastpath := false
				for idx, rule := range rules {
					parsed, pw := parseRule(rule, family, tableName, &setUsage, &mapUsage, unhandledTypes)
					addWarnings(&info, "parser", pw)
					parsed.Table = tableName
					parsed.Chain = ch.Name
					parsed.Index = idx + 1
					parsed.Expr = buildExpr(parsed.Matches, parsed.Verdict)
					parsed.Fingerprint = normalizeFingerprint(parsed.Matches, parsed.Verdict)

					chainInfo.PacketCount += parsed.Packets
					chainInfo.ByteCount += parsed.Bytes
					summary.collectRule(parsed)

					if contains(parsed.Tags, TagMasq) {
						hasMasq = true
					}

					if contains(parsed.Tags, TagEstablished) {
						establishedSeen = true
						if (chainInfo.Hook == "input" || chainInfo.Hook == "forward" || chainInfo.Hook == "output") && !narrowMatchSeen {
							chainHasFastpath = true
						}
					}

					if len(parsed.Matches) > 0 && parsed.Verdict != "" {
						narrowMatchSeen = true
					}

					for _, vp := range cfg.ExpectedVPNPorts {
						protoMatch := fmt.Sprintf("proto=%s", vp.Proto)
						if parsed.Verdict == "ACCEPT" && contains(parsed.Matches, protoMatch) && (chainInfo.Hook == "input" || chainInfo.Hook == "prerouting") {
							covered, unknown := portCovered(parsed.Matches, vp.Port, "dpt", setPreviews)
							if covered {
								key := fmt.Sprintf("%s_%d", vp.Proto, vp.Port)
								vpnAcceptFound[key] = true
							} else if unknown {
								key := fmt.Sprintf("%s/%d", vp.Proto, vp.Port)
								vpnUnknownCoverage[key] = struct{}{}
							}
						}
					}

					if parsed.Verdict == "ACCEPT" && len(parsed.Matches) > 0 {
						hasAccept = true
					}
					if *cfg.WarnShadowing && chainInfo.Policy != "ACCEPT" && parsed.Verdict == "DROP" && len(parsed.Matches) == 0 {
						broadDropSeen = true
					}
					if parsed.Verdict == "RETURN" || (parsed.Verdict == "JUMP" && len(parsed.Matches) == 0) {
						broadDropSeen = false
					}
					if *cfg.WarnShadowing && broadDropSeen && parsed.Verdict == "ACCEPT" && len(parsed.Matches) > 0 && !shadowWarned {
						addWarning(&info, "shadowing", fmt.Sprintf("Возможен shadowing: широкое DROP выше, чем более специфичный ACCEPT (%s/%s)", tableName, ch.Name))
						shadowWarned = true
					}

					// Chain usage for JUMP
					for _, e := range rule.Exprs {
						if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictJump && v.Chain != "" {
							chainKey := fmt.Sprintf("%s_%s", tableName, v.Chain)
							chainUsage[chainKey] = true
						}
					}

					chainInfo.Rules = append(chainInfo.Rules, parsed)
					info.Counts["rules_total"]++
					if len(flatRules) < MaxFlatRules {
						flatRules = append(flatRules, parsed)
					}
				} // конец цикла по правилам

				// пост-эвристики по цепи
				if establishedSeen && (chainInfo.Hook == "input" || chainInfo.Hook == "forward" || chainInfo.Hook == "output") && !chainHasFastpath {
					addWarning(&info, "policy", fmt.Sprintf("ESTABLISHED fastpath not early in base chain %s/%s", tableName, ch.Name))
				}
				if chainHasFastpath {
					info.HasEstablishedFastpath = true
				}
				if chainInfo.Policy == "DROP" && !hasAccept {
					addWarning(&info, "policy", fmt.Sprintf("Блокирующая политика без исключений в %s/%s", tableName, ch.Name))
				}
				tableInfo.Chains = append(tableInfo.Chains, chainInfo)
				info.Counts["chains_total"]++
			}
			// Collect sets
			sets, err := listSetsOfTable(conn, tbl)
			if err == nil {
				for _, s := range sets {
					elements, _ := conn.GetSetElements(s)
					count := len(elements)
					preview := make([]string, 0, MaxSetPreview)
					for i, elem := range elements {
						if i >= MaxSetPreview {
							break
						}
						var val string
						if len(elem.Key) == 2 {
							val = strconv.Itoa(int(be16(elem.Key)))
						} else {
							val = fmt.Sprintf("%v", elem.Key)
						}
						preview = append(preview, val)
					}
					keyType := fmt.Sprintf("%v", s.KeyType)
					set := NFTSet{Name: s.Name, Family: family, Table: tableName, Type: "set", KeyType: keyType, Elements: count, Preview: preview}
					info.Sets = append(info.Sets, set)
					setKey := fmt.Sprintf("%s:%s", tableName, s.Name)
					setPreviews[setKey] = preview
					info.Counts["sets_total"]++
				}
			} else {
				addWarning(&info, "objects", fmt.Sprintf("list sets for %s: %v", tableName, err))
			}

			// Collect maps, flowtables, fill usage if applicable

			tableInfos = append(tableInfos, tableInfo)
			info.Counts["tables_total"]++
		}

		// Mark orphans for sets only, since usage filled
		for i := range info.Sets {
			key := fmt.Sprintf("%s:%s", info.Sets[i].Table, info.Sets[i].Name)
			if !setUsage[key] {
				info.Sets[i].Orphan = true
				addWarning(&info, "objects", fmt.Sprintf("orphan set: %s", key))
			}
		}
		// No orphan for maps/flowtables until usage filled

		// VPN warnings
		if cfg.DeploymentRole != "vpn_client_only" {
			for key, found := range vpnAcceptFound {
				if !found {
					missingVPN = append(missingVPN, strings.Replace(key, "_", "/", -1))
				}
			}
			sort.Strings(missingVPN)
			if len(missingVPN) > 0 {
				addWarning(&info, "openvpn", fmt.Sprintf("Не найдено ACCEPT для VPN портов: %s (INPUT/prerouting)", strings.Join(missingVPN, ", ")))
			}
			unknownList := setToSortedSliceStruct(vpnUnknownCoverage)
			if len(unknownList) > 0 {
				addWarning(&info, "openvpn", fmt.Sprintf("Не могу подтвердить покрытие для портов: %s (множество большое/обрезано; предпросмотр обрезан до %d элементов)", strings.Join(unknownList, ", "), MaxSetPreview))
			}
		}

		if *cfg.WarnNoNat && cfg.DeploymentRole == "vpn_gateway_nat" && !hasMasq {
			addWarning(&info, "nat", "Не обнаружен MASQUERADE (NAT) — возможно, трафик из туннеля не выходит")
		}

		// Unhandled types
		unhandledList := setToSortedSliceBool(unhandledTypes)
		if len(unhandledList) > MaxUnhandledTypes {
			addWarning(&info, "parser", fmt.Sprintf("Unhandled expression types: %s and %d more", strings.Join(unhandledList[:MaxUnhandledTypes], ", "), len(unhandledList)-MaxUnhandledTypes))
		} else {
			for _, t := range unhandledList {
				addWarning(&info, "parser", fmt.Sprintf("unhandled expression type: %s", t))
			}
		}

		info.Tables = tableInfos
		info.FlatRules = flatRules
		info.Summary = summary.finalize()
		info.Counts["rules_shown"] = len(flatRules)
		if info.Counts["rules_total"] > MaxFlatRules {
			addWarning(&info, "parser", fmt.Sprintf("Flat rules truncated to %d; shown %d of %d total", MaxFlatRules, info.Counts["rules_shown"], info.Counts["rules_total"]))
		}
	}

	// Routing context
	hasRoute, uplinks, routeErr := getDefaultRouteInfo()
	info.HasDefaultRoute = hasRoute
	info.UplinkIfaces = uplinks
	mtuMismatches := detectMTUMismatches(uplinks)
	info.MTUMismatchDetected = len(mtuMismatches) > 0
	if info.MTUMismatchDetected {
		addWarnings(&info, "routing", mtuMismatches)
	}
	if routeErr != nil {
		addWarning(&info, "routing", "probe failed")
	} else if !hasRoute {
		addWarning(&info, "routing", "No default route detected (IPv4 or IPv6)")
	}

	return info, nil
}

func listChainsOfTable(conn *nftables.Conn, tbl *nftables.Table) ([]*nftables.Chain, error) {
	chains, err := conn.ListChains()
	if err != nil {
		return nil, err
	}
	filtered := make([]*nftables.Chain, 0)
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == tbl.Name && ch.Table.Family == tbl.Family {
			filtered = append(filtered, ch)
		}
	}
	return filtered, nil
}

func sortTables(tables []*nftables.Table) {
	sort.Slice(tables, func(i, j int) bool {
		if tables[i].Family == tables[j].Family {
			return tables[i].Name < tables[j].Name
		}
		return tables[i].Family < tables[j].Family
	})
}

func sortChains(chains []*nftables.Chain) {
	sort.Slice(chains, func(i, j int) bool {
		hi := hookString(chains[i].Hooknum)
		hj := hookString(chains[j].Hooknum)
		if hi == hj {
			return chains[i].Name < chains[j].Name
		}
		return hi < hj
	})
}

func tableFullName(tbl *nftables.Table) string {
	return fmt.Sprintf("%s/%s", familyString(tbl.Family), tbl.Name)
}

func familyString(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyNetdev:
		return "netdev"
	default:
		return fmt.Sprintf("%d", f)
	}
}

func hookString(h *nftables.ChainHook) string {
	switch h {
	case nil:
		return ""
	case nftables.ChainHookPrerouting:
		return "prerouting"
	case nftables.ChainHookInput:
		return "input"
	case nftables.ChainHookForward:
		return "forward"
	case nftables.ChainHookOutput:
		return "output"
	case nftables.ChainHookPostrouting:
		return "postrouting"
	case nftables.ChainHookIngress:
		return "ingress"
	default:
		if h == nil {
			return ""
		}
		return fmt.Sprintf("%d", *h)
	}
}

func policyString(p *nftables.ChainPolicy) string {
	if p == nil {
		return ""
	}
	switch *p {
	case nftables.ChainPolicyAccept:
		return "ACCEPT"
	case nftables.ChainPolicyDrop:
		return "DROP"
	default:
		return ""
	}
}

func buildExpr(matches []string, verdict string) string {
	expr := strings.Join(matches, " ")
	if verdict != "" {
		if expr != "" {
			expr += " -> "
		}
		expr += verdict
	}
	return expr
}

func normalizeMatch(m string) string {
	return m
}

func listSetsOfTable(conn *nftables.Conn, tbl *nftables.Table) ([]*nftables.Set, error) {
	_ = conn
	_ = tbl
	return []*nftables.Set{}, nil
}

func setToSortedSliceBool(m map[string]bool) []string {
	res := make([]string, 0, len(m))
	for k := range m {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
}

func setToSortedSliceStruct(m map[string]struct{}) []string {
	res := make([]string, 0, len(m))
	for k := range m {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
}

// fallbackCollectViaNftJSON implements partial snapshot.
func fallbackCollectViaNftJSON(ctx context.Context) (FirewallInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "-j", "list", "ruleset")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return FirewallInfo{}, fmt.Errorf("nft command failed: %v, stderr: %s", err, stderr.String())
	}

	var nftJSON struct {
		Nftables []map[string]interface{} `json:"nftables"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &nftJSON); err != nil {
		return FirewallInfo{}, err
	}

	partial := FirewallInfo{PartialMode: true}
	tableMap := make(map[string]*NFTTable)

	getTable := func(fam, name string) *NFTTable {
		full := fam + " " + name
		tbl, ok := tableMap[full]
		if !ok {
			tbl = &NFTTable{Name: full, Family: fam}
			tableMap[full] = tbl
		}
		return tbl
	}

	for _, item := range nftJSON.Nftables {
		if tbl, ok := item["table"].(map[string]interface{}); ok {
			fam, _ := tbl["family"].(string)
			name, _ := tbl["name"].(string)
			_ = getTable(fam, name)
			continue
		}
		if ch, ok := item["chain"].(map[string]interface{}); ok {
			fam, _ := ch["family"].(string)
			tname, _ := ch["table"].(string)
			cname, _ := ch["name"].(string)

			var hook, policy string
			if h, ok := ch["hook"].(string); ok {
				hook = strings.ToLower(h)
			} else if hnum, ok := ch["hooknum"].(float64); ok {
				hook = jsonHooknumToString(int(hnum))
			}

			if p, ok := ch["policy"].(string); ok {
				policy = strings.ToUpper(p)
			}

			tbl := getTable(fam, tname)
			tbl.Chains = append(tbl.Chains, NFTChain{
				Name:   cname,
				Hook:   hook,
				Policy: policy,
			})
			continue
		}
		if rule, ok := item["rule"].(map[string]interface{}); ok {
			fam, _ := rule["family"].(string)
			tname, _ := rule["table"].(string)
			cname, _ := rule["chain"].(string)
			parsed := NFTRule{Table: fam + " " + tname, Chain: cname}
			if exprs, ok := rule["expr"].([]interface{}); ok {
				for _, eAny := range exprs {
					e, _ := eAny.(map[string]interface{})
					if v, ok := e["verdict"].(map[string]interface{}); ok {
						if kind, ok := v["kind"].(string); ok {
							parsed.Verdict = strings.ToUpper(kind)
						}
					}
				}
			}
			tbl := getTable(fam, tname)
			for i := range tbl.Chains {
				if tbl.Chains[i].Name == cname {
					tbl.Chains[i].Rules = append(tbl.Chains[i].Rules, parsed)
					break
				}
			}
			partial.FlatRules = append(partial.FlatRules, parsed)
		}
	}

	names := make([]string, 0, len(tableMap))
	for k := range tableMap {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		partial.Tables = append(partial.Tables, *tableMap[k])
	}
	return partial, nil
}

func jsonHooknumToString(n int) string {
	switch n {
	case 0:
		return "prerouting"
	case 1:
		return "input"
	case 2:
		return "forward"
	case 3:
		return "output"
	case 4:
		return "postrouting"
	default:
		return ""
	}
}

// getDefaultRouteInfo using netlink.
func getDefaultRouteInfo() (bool, []string, error) {
	uplinks := make(map[string]bool)
	var lastErr error
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteList(nil, family)
		if err != nil {
			lastErr = err
			continue
		}
		for _, route := range routes {
			if route.Dst == nil {
				link, err := netlink.LinkByIndex(route.LinkIndex)
				if err == nil {
					uplinks[link.Attrs().Name] = true
				}
			}
		}
	}
	var uplinkList []string
	for up := range uplinks {
		uplinkList = append(uplinkList, up)
	}
	sort.Strings(uplinkList)
	if len(uplinkList) == 0 {
		if lastErr != nil {
			return false, nil, lastErr
		}
		return false, nil, nil
	}
	return true, uplinkList, nil
}

// portCovered with unknown.
func portCovered(matches []string, port uint16, fieldPrefix string, setPreviews map[string][]string) (bool, bool) { // covered, unknown
	portStr := strconv.Itoa(int(port))
	for _, m := range matches {
		if strings.HasPrefix(m, fieldPrefix+"=") && strings.TrimPrefix(m, fieldPrefix+"=") == portStr {
			return true, false
		}
		if strings.HasPrefix(m, fieldPrefix+" in ") {
			rangeStr := strings.TrimPrefix(m, fieldPrefix+" in ")
			if strings.HasPrefix(rangeStr, "{") {
				set := strings.Trim(rangeStr, "{}")
				ports := strings.Split(set, ",")
				for _, p := range ports {
					if strings.TrimSpace(p) == portStr {
						return true, false
					}
				}
				return false, false
			} else {
				setName := strings.TrimSpace(rangeStr)
				preview, ok := setPreviews[setName]
				if ok {
					for _, p := range preview {
						if p == portStr {
							return true, false
						}
					}
					if len(preview) >= MaxSetPreview {
						return false, true // Unknown
					}
					return false, false
				}
				return false, true // Unknown if set not found
			}
		}
	}
	return false, false
}

// normalizeFingerprint with ordered fields.
func normalizeFingerprint(matches []string, verdict string) string {
	var ct, ip, proto, ports, ranges, sets []string
	for _, m := range matches {
		norm := normalizeMatch(m)
		norm = strings.Join(strings.Fields(norm), " ")
		if strings.HasPrefix(norm, "ct=") {
			ct = append(ct, norm)
		} else if strings.HasPrefix(norm, "ip ") || strings.HasPrefix(norm, "ip6 ") || strings.HasPrefix(norm, "src=") || strings.HasPrefix(norm, "dst=") {
			ip = append(ip, norm)
		} else if strings.HasPrefix(norm, "proto=") {
			proto = append(proto, norm)
		} else if strings.HasPrefix(norm, "spt=") || strings.HasPrefix(norm, "dpt=") {
			ports = append(ports, norm)
		} else if strings.Contains(norm, " in ") && strings.Contains(norm, "-") {
			ranges = append(ranges, norm)
		} else if strings.Contains(norm, " in ") {
			sets = append(sets, norm)
		}
	}
	sort.Strings(ct)
	sort.Strings(ip)
	sort.Strings(proto)
	sort.Strings(ports)
	sort.Strings(ranges)
	sort.Strings(sets)
	normMatches := append(append(append(append(append(append([]string{}, ct...), ip...), proto...), ports...), ranges...), sets...)
	expr := strings.Join(normMatches, " ")
	if verdict != "" {
		if expr != "" {
			expr += " -> "
		}
		expr += verdict
	}
	return expr
}

func (s *summaryBuilder) finalize() FirewallStats {
	families := make([]string, 0, len(s.families))
	for f := range s.families {
		families = append(families, f)
	}
	sort.Strings(families)

	basePolicies := make(map[string]string, len(s.basePolicies))
	for k, v := range s.basePolicies {
		basePolicies[k] = v
	}

	verdictKeys := make([]string, 0, len(s.verdicts))
	for k := range s.verdicts {
		verdictKeys = append(verdictKeys, k)
	}
	sort.Strings(verdictKeys)

	byVerdict := make([]VerdictAgg, 0, len(verdictKeys))
	for _, v := range verdictKeys {
		agg := s.verdicts[v]
		byVerdict = append(byVerdict, VerdictAgg{Verdict: v, Packets: agg.Packets, Bytes: agg.Bytes})
	}

	// Покрытие интерфейсов
	iifList := make([]string, 0, len(s.iif))
	for k := range s.iif {
		iifList = append(iifList, k)
	}
	sort.Strings(iifList)

	oifList := make([]string, 0, len(s.oif))
	for k := range s.oif {
		oifList = append(oifList, k)
	}
	sort.Strings(oifList)

	allSet := make(map[string]struct{})
	for _, k := range iifList {
		allSet[k] = struct{}{}
	}
	for _, k := range oifList {
		allSet[k] = struct{}{}
	}
	allList := make([]string, 0, len(allSet))
	for k := range allSet {
		allList = append(allList, k)
	}
	sort.Strings(allList)

	ifaceCoverage := IfaceCoverage{
		IIF: iifList,
		OIF: oifList,
		All: allList,
	}

	// Агрегация по тегам
	tagKeys := make([]string, 0, len(s.tagsAgg))
	for k := range s.tagsAgg {
		tagKeys = append(tagKeys, k)
	}
	sort.Strings(tagKeys)

	tagsAgg := make([]TagAgg, 0, len(tagKeys))
	for _, k := range tagKeys {
		agg := s.tagsAgg[k]
		tagsAgg = append(tagsAgg, TagAgg{
			Tag:     k,
			Packets: agg.Packets,
			Bytes:   agg.Bytes,
		})
	}

	return FirewallStats{
		Families:      families,
		BasePolicies:  basePolicies,
		Totals:        s.totals,
		ByVerdict:     byVerdict,
		IfaceCoverage: ifaceCoverage,
		TagsAgg:       tagsAgg,
	}
}

// collectBasePolicy prioritize inet
func (s *summaryBuilder) collectBasePolicy(key, policy string) {
	parts := strings.SplitN(key, "_", 2)
	if len(parts) != 2 {
		return
	}
	fam, hook := parts[0], parts[1]

	if fam == "inet" {
		s.basePolicies[hook] = policy
	} else if _, ok := s.basePolicies[hook]; !ok {
		s.basePolicies[hook] = policy
	}
}

func addWarning(info *FirewallInfo, cat, warn string) {
	if len(info.Warnings[cat]) < MaxWarningsPerCategory {
		info.Warnings[cat] = append(info.Warnings[cat], warn)
	}
}

func addWarnings(info *FirewallInfo, cat string, warns []string) {
	for _, w := range warns {
		addWarning(info, cat, w)
	}
}

func IsFirewallPermissionError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func detectMTUMismatches(uplinks []string) []string {
	if len(uplinks) == 0 {
		return nil
	}
	up := uplinks[0]
	ifaces, _ := net.Interfaces()
	var upMTU int
	tun := make(map[string]int)

	for _, ifc := range ifaces {
		if ifc.Name == up {
			upMTU = ifc.MTU
		}
		if strings.HasPrefix(ifc.Name, "tun") || strings.HasPrefix(ifc.Name, "tap") || strings.HasPrefix(ifc.Name, "wg") {
			tun[ifc.Name] = ifc.MTU
		}
	}

	var warns []string
	for name, mtu := range tun {
		d := mtu - upMTU
		if d < 0 {
			d = -d
		}
		if d == 0 {
			continue
		}
		if containsInt(MTUAllowedDeltas, d) {
			continue
		}
		if d >= MTUThreshold {
			warns = append(warns,
				fmt.Sprintf("MTU mismatch: %s (%d) vs %s (%d), delta %d",
					name, mtu, up, upMTU, d))
		}
	}
	sort.Strings(warns)
	return warns
}

func containsInt(list []int, v int) bool {
	for _, i := range list {
		if i == v {
			return true
		}
	}
	return false
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// parseRule — парсер правила с извлечением proto/src/dst/портов/iif/oif + NAT.
func parseRule(
	rule *nftables.Rule,
	family string,
	tableName string,
	setUsage *map[string]bool,
	mapUsage *map[string]bool,
	unhandledTypes map[string]bool,
) (NFTRule, []string) {

	var (
		matches    []string
		verdict    string
		jumpTarget string
		pkts       uint64
		byteCount  uint64
		tags       []string
		warns      []string

		lastField string

		l4proto string
		srcIP   string
		dstIP   string
		varSport *uint16
		varDport *uint16
		inIface  string
		outIface string

		expectCmp string

		// Ct state (ESTABLISHED)
		ctSeen  bool
		ctMask  []byte
		ctValue []byte

		// IP-адрес с возможной маской (для сетей 10.8.0.0/16 и т.п.)
		ipMatchPending bool   // ждём Cmp для IP после Payload(+Bitwise)
		ipMask         []byte // маска из Bitwise
		// Признак, что таргет уже выбран NAT-экшеном (MASQUERADE/SNAT/DNAT)
		natTargetSeen bool
	)

	_ = tableName
	_ = mapUsage

	for _, ex := range rule.Exprs {
		switch e := ex.(type) {

		case *expr.Meta:
			switch e.Key {
			case expr.MetaKeyL4PROTO:
				expectCmp = "l4proto"
			case expr.MetaKeyIIFNAME:
				expectCmp = "iifname"
			case expr.MetaKeyOIFNAME:
				expectCmp = "oifname"
			default:
				// остальные meta пока не трогаем
			}

		case *expr.Payload:
			// ip protocol: IP header, offset 9, 1 байт
			if e.Base == expr.PayloadBaseNetworkHeader && e.Offset == 9 && e.Len == 1 {
				expectCmp = "ipproto"
			}

			// L4 порты
			if e.Base == expr.PayloadBaseTransportHeader && e.Len == 2 {
				switch e.Offset {
				case 0:
					expectCmp = "spt"
				case 2:
					expectCmp = "dpt"
				}
			}

			// IPv4/IPv6 адреса
			if e.Base == expr.PayloadBaseNetworkHeader {
				if e.Len == 4 {
					switch e.Offset {
					case 12:
						expectCmp = "ip_saddr"
						ipMatchPending = true
						ipMask = nil
					case 16:
						expectCmp = "ip_daddr"
						ipMatchPending = true
						ipMask = nil
					}
				} else if e.Len == 16 {
					switch e.Offset {
					case 8:
						expectCmp = "ip6_saddr"
						ipMatchPending = true
						ipMask = nil
					case 24:
						expectCmp = "ip6_daddr"
						ipMatchPending = true
						ipMask = nil
					}
				}
			}

		case *expr.Lookup:
			setName := strings.TrimSpace(e.SetName)
			if setName != "" {
				key := fmt.Sprintf("%s:%s", tableName, setName)
				(*setUsage)[key] = true

				if lastField != "" {
					matches = append(matches, fmt.Sprintf("%s in %s", lastField, key))
				} else {
					matches = append(matches, fmt.Sprintf("lookup in %s", key))
				}
			}

		case *expr.Counter:
			pkts += e.Packets
			byteCount += e.Bytes

        case *expr.Masq:
            // Нативный MASQUERADE
            verdict = "MASQUERADE"
            if !contains(tags, TagMasq) {
                tags = append(tags, TagMasq)
            }
            natTargetSeen = true

        case *expr.Redir:
            // Нативный redirect
            verdict = "REDIRECT"
            if !contains(tags, TagRedir) {
                tags = append(tags, TagRedir)
            }
            natTargetSeen = true

        case *expr.Target:
            // iptables-nft совместимый слой:
            // -j MASQUERADE / DNAT / SNAT / REDIRECT / LOG / REJECT / ...
            name := strings.ToUpper(e.Name)

            switch name {
            case "MASQUERADE":
                // iptables: -t nat -A POSTROUTING ... -j MASQUERADE
                if verdict == "" {
                    verdict = "MASQUERADE"
                }
                if !contains(tags, TagMasq) {
                    tags = append(tags, TagMasq)
                }
                natTargetSeen = true

            case "REDIRECT":
                // iptables: -j REDIRECT
                if verdict == "" {
                    verdict = "REDIRECT"
                }
                if !contains(tags, TagRedir) {
                    tags = append(tags, TagRedir)
                }
                natTargetSeen = true

            case "DNAT", "SNAT", "NETMAP":
                // iptables: -j DNAT/SNAT/NETMAP
                // В iptables это именно target-колонка, поэтому
                // просто кладём в Verdict, чтобы UI совпадал.
                if verdict == "" {
                    verdict = name
                }
                natTargetSeen = true

            case "LOG":
                // iptables: -j LOG
                if verdict == "" {
                    verdict = "LOG"
                }
                // Чтобы в Expr было видно, что тут логирование
                matches = append(matches, "target=LOG")

            case "REJECT":
                // iptables: -j REJECT
                if verdict == "" {
                    verdict = "REJECT"
                }

            default:
                // Незнакомый таргет — хотя бы отобразим его в Expr,
                // чтобы не потерять информацию.
                matches = append(matches, "target="+name)
            }

        case *expr.Ct:
            if e.Key == expr.CtKeySTATE {
                ctSeen = true
            }

        case *expr.Bitwise:
            // Ct state маска
            if ctSeen && len(e.Mask) > 0 {
                ctMask = append([]byte(nil), e.Mask...)
            }
            // Маска для IP-адреса (сеть)
            if ipMatchPending && len(e.Mask) > 0 {
                ipMask = append([]byte(nil), e.Mask...)
            }

        case *expr.Cmp:
            switch {
            // L4 proto (Meta(L4PROTO) или ip protocol из IP-заголовка)
            case (expectCmp == "l4proto" || expectCmp == "ipproto") && len(e.Data) == 1:
                switch e.Data[0] {
                case 6:
                    l4proto = "tcp"
                    matches = append(matches, "proto=tcp")
                case 17:
                    l4proto = "udp"
                    matches = append(matches, "proto=udp")
                case 1:
                    l4proto = "icmp"
                    matches = append(matches, "proto=icmp")
                case 58:
                    l4proto = "icmpv6"
                    matches = append(matches, "proto=icmpv6")
                default:
                    l4proto = fmt.Sprintf("0x%02x", e.Data[0])
                    matches = append(matches, fmt.Sprintf("proto=%s", l4proto))
                }
                expectCmp = ""

            // Порты
            case (expectCmp == "spt" || expectCmp == "dpt") && len(e.Data) == 2:
                port := be16(e.Data)
                p := uint16(port)
                if expectCmp == "spt" {
                    matches = append(matches, fmt.Sprintf("spt=%d", port))
                    lastField = "spt"
                    varSport = &p
                } else {
                    matches = append(matches, fmt.Sprintf("dpt=%d", port))
                    lastField = "dpt"
                    varDport = &p
                }
                expectCmp = ""

            // IP / IP6 адреса с учётом возможной маски (сети)
            case ipMatchPending && (len(e.Data) == 4 || len(e.Data) == 16):
                ip := net.IP(e.Data)
                text := ip.String()

                if len(ipMask) > 0 {
                    mask := net.IPMask(ipMask)
                    ones, bits := mask.Size()
                    if ones > 0 && bits > 0 && ones < bits {
                        text = (&net.IPNet{IP: ip, Mask: mask}).String()
                    }
                }

                switch expectCmp {
                case "ip_saddr", "ip6_saddr":
                    srcIP = text
                    matches = append(matches, "src="+text)
                case "ip_daddr", "ip6_daddr":
                    dstIP = text
                    matches = append(matches, "dst="+text)
                }

                expectCmp = ""
                ipMatchPending = false
                ipMask = nil

            // Fallback: голые IP без маски
            case strings.HasPrefix(expectCmp, "ip") && (len(e.Data) == 4 || len(e.Data) == 16):
                ip := net.IP(e.Data).String()
                switch expectCmp {
                case "ip_saddr", "ip6_saddr":
                    srcIP = ip
                    matches = append(matches, "src="+ip)
                case "ip_daddr", "ip6_daddr":
                    dstIP = ip
                    matches = append(matches, "dst="+ip)
                }
                expectCmp = ""
                ipMatchPending = false
                ipMask = nil

            // IIF/OIF имя
            case expectCmp == "iifname" || expectCmp == "oifname":
                nameBytes := e.Data
                if idx := bytes.IndexByte(nameBytes, 0); idx >= 0 {
                    nameBytes = nameBytes[:idx]
                }
                name := string(nameBytes)
                if expectCmp == "iifname" {
                    inIface = name
                    matches = append(matches, "iif="+name)
                } else {
                    outIface = name
                    matches = append(matches, "oif="+name)
                }
                expectCmp = ""

            // Ct state завершение
            case ctSeen && len(e.Data) > 0:
                ctValue = append([]byte(nil), e.Data...)
                if len(ctMask) > 0 && (ctValue[0]&ctMask[0])&0x02 == 0x02 {
                    if !contains(tags, TagEstablished) {
                        tags = append(tags, TagEstablished)
                    }
                    matches = append(matches, "ct=established")
                }
                ctSeen, ctMask, ctValue = false, nil, nil
            }

        case *expr.Verdict:
            lastField = ""
            if natTargetSeen {
                break
            }
            switch e.Kind {
            case expr.VerdictAccept:
                verdict = "ACCEPT"
            case expr.VerdictDrop:
                verdict = "DROP"
            case expr.VerdictReturn:
                verdict = "RETURN"
            case expr.VerdictJump:
                if verdict == "" {
                    verdict = "JUMP"
                }
                if e.Chain != "" {
                    jumpTarget = e.Chain
                }
            default:
                // оставляем как есть
            }

        default:
            tn := fmt.Sprintf("%T", e)
            unhandledTypes[tn] = true
        }
    } // <- закрываем for/switch блоки

    out := NFTRule{
        Matches:    matches,
        Verdict:    verdict,
        JumpTarget: jumpTarget,
        Packets:    pkts,
        Bytes:      byteCount,
        Tags:       tags,
        Proto:      l4proto,
        Src:        srcIP,
        Dst:        dstIP,
        InIface:    inIface,
        OutIface:   outIface,
    }

    if varSport != nil {
        out.Sport = varSport
    }
    if varDport != nil {
        out.Dport = varDport
    }

    // iptables-like синтез для NAT-правил:
    // если протокол/адреса не заданы явно, считаем их "all" и 0.0.0.0/0|::/0
    // и ПРИ ЭТОМ добавляем их в matches, чтобы UI мог парсить из Expr.
    isNAT := verdict == "MASQUERADE" ||
        verdict == "SNAT" ||
        verdict == "DNAT" ||
        verdict == "REDIRECT"

    if isNAT {
        // Протокол
        if l4proto == "" {
            l4proto = "all"
            // если фронт вытаскивает proto из Expr по "proto=", даём ему зацепку
            matches = append(matches, "proto=all")
        }

        // Источник
        if srcIP == "" {
            switch family {
            case "ip6":
                srcIP = "::/0"
            default:
                srcIP = "0.0.0.0/0"
            }
            matches = append(matches, "src="+srcIP)
        }

        // Назначение
        if dstIP == "" {
            switch family {
            case "ip6":
                dstIP = "::/0"
            default:
                dstIP = "0.0.0.0/0"
            }
            matches = append(matches, "dst="+dstIP)
        }
    }

    out := NFTRule{
        Matches:    matches,
        Verdict:    verdict,
        JumpTarget: jumpTarget,
        Packets:    pkts,
        Bytes:      byteCount,
        Tags:       tags,
        Proto:      l4proto,
        Src:        srcIP,
        Dst:        dstIP,
        InIface:    inIface,
        OutIface:   outIface,
    }

    if varSport != nil {
        out.Sport = varSport
    }
    if varDport != nil {
        out.Dport = varDport
    }

    return out, warns
}

// be16 — big-endian → uint16
func be16(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}
