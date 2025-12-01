package lib

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// GenerateUIDataReport writes a Markdown description of data sources and contracts
// to the provided path. It is called on startup so operators can inspect
// collection capabilities without digging into the code.
func GenerateUIDataReport(path string) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "# NiceVPN UI – отчет по данным\nДата генерации: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	b.WriteString("## Источники данных\n")
	b.WriteString("- Management-команды: **version**, **load-stats**, **status 3** (fallback **status 2**), потоки **state/log/bytecount**.\n")
	b.WriteString("- Срез для UI отдается по эндпойнту **/ui/statusz.json** (рекомендуемый для поллинга). Расширенный контракт совпадает с /ui/metrics.json.\n\n")

	b.WriteString("## Контракт /ui/statusz.json\n")
	b.WriteString("Полезная нагрузка включает данные с management/status и базу метрик за 24 часа:\n\n")
	b.WriteString("```json\n")
	b.WriteString("{\n")
	b.WriteString("  \"ovstats\": {\"NClients\": 5, \"BytesIn\": 21718492, \"BytesOut\": 21017334, \"Uptime\": 84672, \"CollectedAt\": \"2025-12-01T19:30:00Z\"},\n")
	b.WriteString("  \"ovstatus\": {\n")
	b.WriteString("    \"ClientList\": [{\"CommonName\": \"alice\", \"RealAddress\": \"203.0.113.10:54321\", \"VirtualAddress\": \"10.8.0.6\", \"BytesReceived\": 123456, \"BytesSent\": 654321, \"ConnectedSince\": \"2025-12-01 18:55:10\", \"Username\": \"UNDEF\"}],\n")
	b.WriteString("    \"GlobalStats\": {\"maxbcastmcastqueuelen\": 0}\n")
	b.WriteString("  },\n")
	b.WriteString("  \"metrics\": {\n")
	b.WriteString("    \"ovdaemon\": {\"state\": \"CONNECTED\"},\n")
	b.WriteString("    \"ovversion\": \"OpenVPN 2.6.17\",\n")
	b.WriteString("    \"management\": {\"state\": 1, \"log\": 1, \"bytecount\": 1},\n")
	b.WriteString("    \"management_reconnects_24h\": 0,\n")
	b.WriteString("    \"global\": {\"max_bcast_mcast_queue_len\": 0},\n")
	b.WriteString("    \"security_24h\": {\"auth_fail\": 0, \"handshake_errors\": 0, \"tls_verify_fail\": 0, \"crl_reject\": 0, \"keepalive_timeouts\": 0},\n")
	b.WriteString("    \"client_breakdown\": [{\"common_name\": \"alice\", \"bytes_in\": 123456, \"bytes_out\": 654321}],\n")
	b.WriteString("    \"last_seen_ts\": \"2025-12-01T19:30:00Z\"\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	b.WriteString("```\n\n")

	b.WriteString("### Пояснения по полям\n")
	b.WriteString("- **ovstats**: snapshot команды load-stats (клиенты, байты, аптайм, метка сбора).\n")
	b.WriteString("- **ovstatus**: сырые клиенты и глобальная статистика из status 3/2 (включая очередь broad/mcast).\n")
	b.WriteString("- **metrics.ovdaemon.state**: состояние демона (CONNECTED/WAIT/RECONNECTING/EXITING/UNKNOWN).\n")
	b.WriteString("- **metrics.management**: наличие потоков state/log/bytecount (1 — активен, 0 — нет).\n")
	b.WriteString("- **metrics.management_reconnects_24h**: счётчик переподключений management за последние 24 часа.\n")
	b.WriteString("- **metrics.security_24h**: агрегаты auth/tls/keepalive/CRL за сутки из сохранённых метрик.\n")
	b.WriteString("- **metrics.client_breakdown**: байты per-client, чтобы строить график распределения.\n")
	b.WriteString("- **metrics.last_seen_ts**: последняя метка получения данных (UTC).\n\n")

	b.WriteString("## Поля на главной\n")
	b.WriteString("- Карточки: подключённые клиенты, загрузка, аптайм ОС, **статус OpenVPN** (плашка + аптайм демона + версия), память/Swap.\n")
	b.WriteString("- Блоки Management, очередь broad/mcast, события безопасности (auth/tls/keepalive), отметка «Обновление».\n")
	b.WriteString("- Графики: serverTotalsChart (BytesIn/BytesOut в MB), clientTrafficChart (breakdown по клиентам в MB).\n\n")

	b.WriteString("## Обновление в реальном времени\n")
	b.WriteString("- Поллинг `/ui/statusz.json` каждые 15 секунд.\n")
	b.WriteString("- Экспоненциальный бэкофф при ошибках до 60 секунд, после успешного ответа возвращаемся к 15 секундам.\n")
	b.WriteString("- Метка обновления подсвечивается красным при устаревании данных > 60 секунд.\n\n")

	b.WriteString("## Интеграционные требования\n")
	b.WriteString("- Бэкенд должен отдавать все поля контракта `/ui/statusz.json` с корректными типами (числа/строки/ISO-8601 timestamps).\n")
	b.WriteString("- Management/status должен быть доступен для live-данных; при недоступности допускается `UNKNOWN` и нули, но структура сохраняется.\n")
	b.WriteString("- Таблицы метрик должны содержать события за последние 24 часа для корректной агрегации security/management счётчиков.\n\n")

	b.WriteString("## Диагностика\n")
	b.WriteString("- Плашки management в красном/жёлтом состоянии сигнализируют об отсутствии потоков/упавшем management.\n")
	b.WriteString("- Красная метка «Обновление» или отсутствие роста байт/клиентов указывает на устаревшие данные.\n")
	b.WriteString("- Ошибки запроса к `/ui/statusz.json` видны в консоли браузера; после восстановления данные подтянутся автоматически.\n")

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return nil
}
