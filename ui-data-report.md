# NiceVPN UI – отчет по данным
Дата генерации: 2025-12-01 18:08:54 UTC

## Источники данных
- Management-команды: **version**, **load-stats**, **status 3** (fallback **status 2**), потоки **state/log/bytecount**.
- Срез для UI отдается по эндпойнту **/ui/statusz.json** (рекомендуемый для поллинга). Расширенный контракт совпадает с /ui/metrics.json.

## Контракт /ui/statusz.json
Полезная нагрузка включает данные с management/status и базу метрик за 24 часа:

```json
{
  "ovstats": {"NClients": 5, "BytesIn": 21718492, "BytesOut": 21017334, "Uptime": 84672, "CollectedAt": "2025-12-01T19:30:00Z"},
  "ovstatus": {
    "ClientList": [{"CommonName": "alice", "RealAddress": "203.0.113.10:54321", "VirtualAddress": "10.8.0.6", "BytesReceived": 123456, "BytesSent": 654321, "ConnectedSince": "2025-12-01 18:55:10", "Username": "UNDEF"}],
    "GlobalStats": {"maxbcastmcastqueuelen": 0}
  },
  "metrics": {
    "ovdaemon": {"state": "CONNECTED"},
    "ovversion": "OpenVPN 2.6.17",
    "management": {"state": 1, "log": 1, "bytecount": 1},
    "management_reconnects_24h": 0,
    "global": {"max_bcast_mcast_queue_len": 0},
    "security_24h": {"auth_fail": 0, "handshake_errors": 0, "tls_verify_fail": 0, "crl_reject": 0, "keepalive_timeouts": 0},
    "client_breakdown": [{"common_name": "alice", "bytes_in": 123456, "bytes_out": 654321}],
    "last_seen_ts": "2025-12-01T19:30:00Z"
  }
}
```

### Пояснения по полям
- **ovstats**: snapshot команды load-stats (клиенты, байты, аптайм, метка сбора).
- **ovstatus**: сырые клиенты и глобальная статистика из status 3/2 (включая очередь broad/mcast).
- **metrics.ovdaemon.state**: состояние демона (CONNECTED/WAIT/RECONNECTING/EXITING/UNKNOWN).
- **metrics.management**: наличие потоков state/log/bytecount (1 — активен, 0 — нет).
- **metrics.management_reconnects_24h**: счётчик переподключений management за последние 24 часа.
- **metrics.security_24h**: агрегаты auth/tls/keepalive/CRL за сутки из сохранённых метрик.
- **metrics.client_breakdown**: байты per-client, чтобы строить график распределения.
- **metrics.last_seen_ts**: последняя метка получения данных (UTC).

## Поля на главной
- Карточки: подключённые клиенты, загрузка, аптайм ОС, **статус OpenVPN** (плашка + аптайм демона + версия), память/Swap.
- Блоки Management, очередь broad/mcast, события безопасности (auth/tls/keepalive), отметка «Обновление».
- Графики: serverTotalsChart (BytesIn/BytesOut в MB), clientTrafficChart (breakdown по клиентам в MB).

## Обновление в реальном времени
- Поллинг `/ui/statusz.json` каждые 15 секунд.
- Экспоненциальный бэкофф при ошибках до 60 секунд, после успешного ответа возвращаемся к 15 секундам.
- Метка обновления подсвечивается красным при устаревании данных > 60 секунд.

## Интеграционные требования
- Бэкенд должен отдавать все поля контракта `/ui/statusz.json` с корректными типами (числа/строки/ISO-8601 timestamps).
- Management/status должен быть доступен для live-данных; при недоступности допускается `UNKNOWN` и нули, но структура сохраняется.
- Таблицы метрик должны содержать события за последние 24 часа для корректной агрегации security/management счётчиков.

## Диагностика
- Плашки management в красном/жёлтом состоянии сигнализируют об отсутствии потоков/упавшем management.
- Красная метка «Обновление» или отсутствие роста байт/клиентов указывает на устаревшие данные.
- Ошибки запроса к `/ui/statusz.json` видны в консоли браузера; после восстановления данные подтянутся автоматически.
