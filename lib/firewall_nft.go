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

	MTUThreshold     = 100
	MTUAllowedDeltas = []int{8, 20, 28, 80} // PPPoE, L2TP, GRE, WG

	SchemaVersion = 2

	ProducerName    = "nft-snapshot"
	ProducerVersion = "1.0.0"
	ProducerAPI     = "grok4"
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

// FirewallInfo represents nftables snapshot for UI.
type FirewallInfo struct {
	Kind                    string              `json:"kind"`
	SchemaVersion           int                 `json:"schema_version"`
	TakenAt                 string              `json:"taken_at"`
	Hostname                string              `json:"hostname"`
	Summary                 FirewallStats       `json:"summary"`
	Tables                  []NFTTable          `json:"tables"`
	FlatRules               []NFTRule           `json:"flat_rules"`
	Sets                    []NFTSet            `json:"sets,omitempty"`
	Maps                    []NFTMap            `json:"maps,omitempty"`
	Flowtables              []NFTFlowtable      `json:"flowtables,omitempty"`
	Warnings                map[string][]string `json:"warnings,omitempty"`
	HasDefaultRoute         bool                `json:"has_default_route"`
	UplinkIfaces            []string            `json:"uplink_ifaces,omitempty"`
	MTUMismatchDetected     bool                `json:"mtu_mismatch_detected"`
	ChainCountersMode       string              `json:"chain_counters_mode"`
	PartialMode             bool                `json:"partial_mode,omitempty"`
	HasEstablishedFastpath  bool                `json:"has_established_fastpath"`
	HasForwardPolicyAccept   bool                `json:"has_forward_policy_accept"`
	HasForwardPolicyDrop     bool                `json:"has_forward_policy_drop"`
	Counts                  map[string]int      `json:"counts,omitempty"` // rules_total, rules_shown, chains_total, tables_total, sets_total, etc.
	Producer                ProducerInfo        `json:"producer"`
}

// ProducerInfo holds producer metadata.
type ProducerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	API     string `json:"api"`
}

// FirewallStats aggregates summary metrics.
type FirewallStats struct {
	Families     []string     `json:"families,omitempty"`
	BasePolicies map[string]string `json:"base_policies,omitempty"`
	Totals       RuleCounters `json:"totals"`
	ByVerdict    []VerdictAgg `json:"by_verdict,omitempty"`
	IfaceCoverage IfaceCoverage `json:"iface_coverage"`
	TagsAgg      []TagAgg     `json:"tags_agg,omitempty"`
	Meta         StatsMeta    `json:"meta,omitempty"`
}

// StatsMeta holds metadata for stats.
type StatsMeta struct {
	CountersMode string `json:"counters_mode,omitempty"`
	FallbackMode bool   `json:"fallback_mode,omitempty"`
	APILevel     string `json:"api_level,omitempty"`
	Note         string `json:"note,omitempty"`
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
	Name    string     `json:"name"`
	Family  string     `json:"family"`
	Chains  []NFTChain `json:"chains"`
}

// NFTChain represents nftables chain.
type NFTChain struct {
	Name        string   `json:"name"`
	Hook        string   `json:"hook"`
	Policy      string   `json:"policy"`
	PacketCount uint64   `json:"packet_count"`
	ByteCount   uint64   `json:"byte_count"`
	Rules       []NFTRule `json:"rules"`
	Orphan      bool     `json:"orphan,omitempty"`
}

// NFTRule represents nftables rule.
type NFTRule struct {
	Table       string   `json:"table"`
	Chain       string   `json:"chain"`
	Index       int      `json:"index"`
	Expr        string   `json:"expr"`
	Verdict     string   `json:"verdict"`
	Matches     []string `json:"matches"`
	Packets     uint64   `json:"packets"`
	Bytes       uint64   `json:"bytes"`
	Tags        []string `json:"tags"`
	Fingerprint string   `json:"fingerprint"`
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
	Name     string   `json:"name"`
	Family   string   `json:"family"`
	Table    string   `json:"table"`
	Type     string   `json:"type"`
	KeyType  string   `json:"key_type,omitempty"`
	MapType  string   `json:"map_type,omitempty"`
	Elements int      `json:"elements"`
	Orphan   bool     `json:"orphan,omitempty"`
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
			// etc
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
		defer conn.Close()
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
	flowtableUsage := make(map[string]bool)

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

			chains, err := conn.ListChainsOfTable(tbl)
			if err != nil {
				addWarning(&info, "parser", fmt.Sprintf("list chains for %s: %v", tableName, err))
				continue
			}

			tableInfo := NFTTable{Name: tableName, Family: family}

            sortChains(chains)
            for _, ch := range chains {
				chainInfo := NFTChain{Name: ch.Name, Hook: hookString(ch.Hooknum), Policy: policyString(ch.Policy)}
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
                } // <-- конец цикла по правилам

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
                           // Для наборов портов ключ обычно 2-байтовый BE-integer.
                           if len(elem.Key) == 2 {
                               val = strconv.Itoa(int(be16(elem.Key)))
                           } else {
                               // Для остальных типов пусть остаётся как раньше.
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
				unknownList := setToSortedSlice(vpnUnknownCoverage)
				if len(unknownList) > 0 {
					addWarning(&info, "openvpn", fmt.Sprintf("Не могу подтвердить покрытие для портов: %s (множество большое/обрезано; предпросмотр обрезан до %d элементов)", strings.Join(unknownList, ", "), MaxSetPreview))
				}
			}

			if *cfg.WarnNoNat && cfg.DeploymentRole == "vpn_gateway_nat" && !hasMasq {
				addWarning(&info, "nat", "Не обнаружен MASQUERADE (NAT) — возможно, трафик из туннеля не выходит")
			}

			// Unhandled types
			unhandledList := setToSortedSlice(unhandledTypes)
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
            // nft -j обычно даёт строковый hook ("input", "forward", ...)
            if h, ok := ch["hook"].(string); ok {
                hook = strings.ToLower(h)
            } else if hnum, ok := ch["hooknum"].(float64); ok {
                // fallback на случай, если когда-то понадобится.
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
                    // meta/payload/ct/lookup — можно дополнять по мере надобности
                }
            }
            tbl := getTable(fam, tname)
            // Найти цепь и добавить правило
            for i := range tbl.Chains {
                if tbl.Chains[i].Name == cname {
                    tbl.Chains[i].Rules = append(tbl.Chains[i].Rules, parsed)
                    break
                }
            }
            partial.FlatRules = append(partial.FlatRules, parsed)
        }
        // sets/maps при желании добавить аналогично
    }

    // Разворачиваем map → slice, сохраняя детерминированный порядок
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

// jsonHooknumToString — соответствие номеров хуков строковым именам
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
       // Если вообще ни один вызов RouteList не удался — это уже probe failed.
       if lastErr != nil {
           return false, nil, lastErr
       }
       // Нет дефолтного маршрута — валидное состояние, не ошибка.
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
	// Order: ct, ip/ip6 saddr/daddr, proto, spt/dpt, ranges, sets
	var ct, ip, proto, ports, ranges, sets []string
	for _, m := range matches {
		norm := normalizeMatch(m)
		norm = strings.Join(strings.Fields(norm), " ") // Collapse spaces
		if strings.HasPrefix(norm, "ct=") {
			ct = append(ct, norm)
		} else if strings.HasPrefix(norm, "ip ") || strings.HasPrefix(norm, "ip6 ") {
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

// In summary.finalize, only terminal verdicts
func (s *summaryBuilder) finalize() FirewallStats {
	stats := FirewallStats{
		// ...
	}
	verdicts := []string{"ACCEPT", "DROP", "RETURN", "MASQUERADE", "REDIRECT"}
	for _, v := range verdicts {
		if agg, ok := s.verdicts[v]; ok {
			stats.ByVerdict = append(stats.ByVerdict, VerdictAgg{Verdict: v, Packets: agg.Packets, Bytes: agg.Bytes})
		}
	}
	// ...
	return stats
}

// (s *summaryBuilder) collectBasePolicy prioritize inet
func (s *summaryBuilder) collectBasePolicy(key, policy string) {
   // key ожидается в формате "<family>_<hook>", например "inet_forward".
   parts := strings.SplitN(key, "_", 2)
   if len(parts) != 2 {
       return
   }
   fam, hook := parts[0], parts[1]

   if fam == "inet" {
       // inet-таблицы считаем источником истины для base policy.
       s.basePolicies[hook] = policy
   } else if _, ok := s.basePolicies[hook]; !ok {
       // ip/ip6 заполняют только если inet ещё не задавал политику.
       s.basePolicies[hook] = policy
   }
}

// Other functions as before.

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
       // Явно whitelisted дельты (PPPoE, L2TP, GRE, WG и т.д.) — не трогаем.
       if containsInt(MTUAllowedDeltas, d) {
           continue
       }
       // Всё остальное, что заметно отличается по MTU, подсвечиваем.
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
    for _, x := range ss { if x == s { return true } }
    return false
}


// parseRule — минимальный парсер для нужд snapshot-а.
// Главное: поддержка expr.Lookup с отметкой setUsage и человекочитаемым match.
// Дополнительно: Counter, Verdict, Masq/Redir в виде вердиктов и тегов.
func parseRule(
	rule *nftables.Rule,
	family string,
	tableName string,
	setUsage *map[string]bool,
	mapUsage *map[string]bool,
	unhandledTypes map[string]bool,
) (NFTRule, []string) {

	var (
		matches []string
		verdict string
		pkts    uint64
		bytes   uint64
		tags    []string
		warns   []string
		// lastField можно заполнять в будущем при разборе payload/meta,
		// чтобы формировать "dpt in table:set". Сейчас оставим пустым.
		lastField string
		// простая внутренняя «машинка» для ct state и l4-полей
		l4proto   string        // "tcp"|"udp"|"..."
		expectCmp string        // "spt"|"dpt" когда предшествовал payload соответствующего оффсета
		ctSeen    bool          // видели Ct{Key:STATE}
		ctMask    []byte
		ctValue   []byte
	)

	_ = family
	_ = mapUsage
	
	for _, ex := range rule.Exprs {
		switch e := ex.(type) {

		case *expr.Meta:
			// l4proto / iif / oif и т.п.
			if e.Key == expr.MetaKeyL4PROTO {
				expectCmp = "l4proto"
			}

		case *expr.Payload:
			// Транспортный заголовок: 0..1 sport, 2..3 dport
			if e.Base == expr.PayloadBaseTransportHeader && e.Len == 2 {
				switch e.Offset {
				case 0:
					expectCmp = "spt"
				case 2:
					expectCmp = "dpt"
				}
			}
			
		case *expr.Lookup:
			// lookup по множеству/карте
			setName := strings.TrimSpace(e.SetName)
			if setName != "" {
				// Ключ использования множества соответствует формату,
				// который затем помечается как orphan/non-orphan: "table:set".
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
			bytes += e.Bytes

		case *expr.Masq:
			verdict = "MASQUERADE"
			if !contains(tags, TagMasq) {
				tags = append(tags, TagMasq)
			}

		case *expr.Redir:
			verdict = "REDIRECT"
			if !contains(tags, TagRedir) {
				tags = append(tags, TagRedir)
			}

		case *expr.Ct:
			// Начало шаблона ct state: Ct{Key:STATE} → Bitwise → Cmp
			if e.Key == expr.CtKeySTATE {
				ctSeen = true
				// значения дочитываем в Bitwise/Cmp
			}

		case *expr.Bitwise:
			// В nft для ct state обычно маска применяется битвайзом
			if ctSeen && len(e.Mask) > 0 {
				ctMask = append([]byte(nil), e.Mask...)
			}

		case *expr.Cmp:
			// Вариант 1: это сравнение после Meta(L4PROTO)
			if expectCmp == "l4proto" && len(e.Data) == 1 {
				switch e.Data[0] {
				case 6:
					l4proto = "tcp"
					matches = append(matches, "proto=tcp")
				case 17:
					l4proto = "udp"
					matches = append(matches, "proto=udp")
				default:
					l4proto = fmt.Sprintf("0x%02x", e.Data[0])
					matches = append(matches, fmt.Sprintf("proto=%s", l4proto))
				}
				expectCmp = ""
			// Вариант 2: сравнение порта после Payload(спорт/дпорт)
            } else if (expectCmp == "spt" || expectCmp == "dpt") && len(e.Data) == 2 {
				port := be16(e.Data)
				if expectCmp == "spt" {
					matches = append(matches, fmt.Sprintf("spt=%d", port))
					lastField = "spt"
				} else {
					matches = append(matches, fmt.Sprintf("dpt=%d", port))
					lastField = "dpt"
				}
				expectCmp = ""
			// Вариант 3: завершение ct state (после Bitwise приходит Cmp со значением)
			} else if ctSeen && len(e.Data) > 0 {
				ctValue = append([]byte(nil), e.Data...)
				// Простая проверка established: бит 0x02
				if len(ctMask) > 0 && (ctValue[0]&ctMask[0])&0x02 == 0x02 {
					if !contains(tags, TagEstablished) {
						tags = append(tags, TagEstablished)
					}
					matches = append(matches, "ct=established")
				}
				// Сбрасываем состояние ct-шаблона
				ctSeen, ctMask, ctValue = false, nil, nil
			}
			
		case *expr.Verdict:
			lastField = ""
			switch e.Kind {
			case expr.VerdictAccept:
				verdict = "ACCEPT"
			case expr.VerdictDrop:
				verdict = "DROP"
			case expr.VerdictReturn:
				verdict = "RETURN"
			case expr.VerdictJump:
				// JUMP — не терминальный, но фиксируем для «тени» и анализа.
				// Финальный verdict может прийти позже; не перетираем терминальный.
				if verdict == "" {
					verdict = "JUMP"
				}
			default:
				// оставляем как есть
			}

		// TODO: разобрать ct-состояния:
		// шаблон обычно: Ct{Key: CtKeySTATE} + Bitwise (маска) + Cmp (значение).
		// При обнаружении Established/New добавить TagEstablished в tags.
		// case *expr.Ct:
		//   // отметим, что тут есть conntrack; реальную фазу определим на паре Bitwise+Cmp
			
		default:
			// Мини-телеметрия о непокрытых типах
			tn := fmt.Sprintf("%T", e)
			unhandledTypes[tn] = true
		}
	}

	// Собираем результат
	out := NFTRule{
		Matches: matches,
		Verdict: verdict,
		Packets: pkts,
		Bytes:   bytes,
		Tags:    tags,
	}
	return out, warns
}

// be16 — big-endian → uint16
func be16(b []byte) uint16 {
	if len(b) < 2 { return 0 }
	return uint16(b[0])<<8 | uint16(b[1])
}

