package metrics

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/beego/beego/v2/core/logs"
)

var (
	reControlTLS = regexp.MustCompile(`Control Channel: (TLSv[0-9\.]+), cipher ([^,]+)`) // tls_version, tls_cipher
	reDataCipher = regexp.MustCompile(`Cipher '([^']+)' initialized with ([0-9]+) bit key`)
	reHMAC       = regexp.MustCompile(`Using ([0-9]+) bit message hash '([^']+)'`)
	reDataAuth   = regexp.MustCompile(`Data Channel: cipher '([^']+)', auth '([^']+)'`)
)

// LogEnricher tails OpenVPN log and enriches session crypto fields.
type LogEnricher struct {
	cfg       MetricsConfig
	store     *SQLiteStore
	log       *logs.BeeLogger
	debug     bool
	warnedErr bool
}

// NewLogEnricher constructs new enricher instance.
func NewLogEnricher(cfg MetricsConfig, store *SQLiteStore, logger *logs.BeeLogger, debug bool) *LogEnricher {
	return &LogEnricher{cfg: cfg, store: store, log: logger, debug: debug}
}

// Run starts background tailing until context is cancelled.
func (l *LogEnricher) Run(ctx context.Context) {
	if l.cfg.OpenVPNLogPath == "" {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var offset int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			off, err := l.processNewLines(ctx, offset)
			if err != nil {
				if !l.warnedErr {
					l.log.Warn("metrics: log enricher disabled: %v", err)
					l.warnedErr = true
				}
				continue
			}
			offset = off
		}
	}
}

func (l *LogEnricher) processNewLines(ctx context.Context, offset int64) (int64, error) {
	f, err := os.Open(l.cfg.OpenVPNLogPath)
	if err != nil {
		return offset, err
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, 0); err != nil {
			return offset, err
		}
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		l.handleLine(ctx, line)
	}
	if err := scanner.Err(); err != nil {
		return offset, err
	}
	pos, _ := f.Seek(0, 1)
	return pos, nil
}

func (l *LogEnricher) handleLine(ctx context.Context, line string) {
	peerToken, message := splitPeerAndMessage(line)
	cn, ip, port := parsePeerToken(peerToken)

	tlsVersion, tlsCipher, cipher, hmac := "", "", "", ""
	keyBits := 0

	if m := reControlTLS.FindStringSubmatch(message); len(m) == 3 {
		tlsVersion = m[1]
		tlsCipher = strings.TrimSpace(m[2])
	}
	if m := reDataCipher.FindStringSubmatch(message); len(m) == 3 {
		cipher = strings.TrimSpace(m[1])
		keyBits, _ = strconv.Atoi(m[2])
	}
	if m := reHMAC.FindStringSubmatch(message); len(m) == 3 {
		hmac = strings.TrimSpace(m[2])
		if kb, err := strconv.Atoi(m[1]); err == nil && keyBits == 0 {
			keyBits = kb
		}
	}
	if m := reDataAuth.FindStringSubmatch(message); len(m) == 3 {
		cipher = strings.TrimSpace(m[1])
		hmac = strings.TrimSpace(m[2])
	}

	if tlsVersion == "" && tlsCipher == "" && cipher == "" && hmac == "" && keyBits == 0 {
		return
	}

	if l.debug {
		l.log.Debug("metrics: log enrichment peer=%s cn=%s tls=%s cipher=%s hmac=%s keybits=%d", peerToken, cn, tlsVersion, cipher, hmac, keyBits)
	}
	_ = l.store.UpdateSessionCryptoFromLog(ctx, cn, "", ip, port, tlsVersion, tlsCipher, cipher, hmac, keyBits)
}

func splitPeerAndMessage(line string) (string, string) {
	idx := strings.Index(line, "us=")
	if idx == -1 {
		return "", line
	}
	after := line[idx:]
	parts := strings.SplitN(after, " ", 3)
	if len(parts) < 3 {
		return "", line
	}
	return parts[1], parts[2]
}

func parsePeerToken(token string) (string, string, int) {
	if token == "" {
		return "", "", 0
	}
	cn := ""
	hostPort := token
	if strings.Contains(token, "/") {
		segs := strings.SplitN(token, "/", 2)
		cn = segs[0]
		hostPort = segs[1]
	}
	host, portStr, err := netSplitHostPortLoose(hostPort)
	if err != nil {
		return cn, hostPort, 0
	}
	port, _ := strconv.Atoi(portStr)
	return cn, host, port
}

func netSplitHostPortLoose(addr string) (string, string, error) {
	if !strings.Contains(addr, ":") {
		return addr, "", fmt.Errorf("missing port")
	}
	return strings.TrimSpace(addr[:strings.LastIndex(addr, ":")]), strings.TrimSpace(addr[strings.LastIndex(addr, ":")+1:]), nil
}
