#!/usr/bin/env python3
"""
NiceVPN event logger for OpenVPN hooks.

Сценарий читает переменные окружения, формирует нормализованную структуру события
и дописывает её одной строкой JSON в файл:

  /var/log/nicevpn/events-YYYYMMDD.jsonl

Основное управление через переменные окружения:

  NICEVPN_EVENT_TYPE      - тип события (session_connect, session_disconnect, tls_verify, auth_attempt, ip_add, ip_delete, ...)
  NICEVPN_LOG_DIR         - директория для логов (по умолчанию /var/log/nicevpn)
  NICEVPN_LOG_PREFIX      - префикс имени файла (по умолчанию events)
  NICEVPN_LOGGER_DEBUG    - если "1", печатает traceback при ошибке
  NICEVPN_LOGGER_STRICT   - если "1", при ошибке возвращает exit code 1 (иначе всегда 0)

Дополнительные данные от хуков (рекомендуется выставлять в скриптах):

  NICEVPN_USERNAME
  NICEVPN_AUTH_METHOD
  NICEVPN_AUTH_RESULT
  NICEVPN_AUTH_REASON
  NICEVPN_MFA_USED
  NICEVPN_MFA_OK
  NICEVPN_IPSETS      - список через запятую (it_department,rd)
  NICEVPN_ROLES       - список через запятую (admin,dev)
  NICEVPN_VPN_IP      - VPN IP, если нужно переопределить ifconfig_pool_remote_ip
  NICEVPN_EVENT_ID    - внешне заданный идентификатор события (иначе генерируется UUID)

Отправка событий в API метрик (опционально):

  NICEVPN_API_URL     - URL для отправки (если не задан, берётся API_URL или значение по умолчанию)
  API_URL             - альтернативное имя переменной для URL (для совместимости с legacy-скриптами)
  NICEVPN_API_DISABLE - если "1", отправка в API отключена
  NICEVPN_API_TIMEOUT - таймаут запроса к API в секундах (по умолчанию 2)
"""

import errno
import json
import os
import sys
import time
import uuid
from pathlib import Path
import urllib.request
import urllib.parse


LOGGER_VERSION = "1.1.0"
# URL по умолчанию совместим с прежним client-event.sh
DEFAULT_API_URL = "http://127.0.0.1:8080/internal/metrics/client-event"
DEFAULT_API_TIMEOUT = 2  # минимальный мягкий таймаут на запрос к API


def parse_int(value):
    """Безопасное преобразование в int, при ошибке/пустом значении возвращает None."""
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def split_csv_env(name):
    """Чтение переменной вида 'a,b,c' -> ['a', 'b', 'c'], пустые элементы отбрасываются."""
    raw = os.environ.get(name, "")
    if not raw:
        return []
    parts = []
    for item in raw.split(","):
        item = item.strip()
        if item:
            parts.append(item)
    return parts


def get_timestamp():
    """
    Таймштамп события — реальное время вызова логгера.
    Оригинальный time_unix от OpenVPN сохраняется в env.
    """
    return int(time.time())


def safe_env():
    """
    Отфильтрованное окружение для логирования. Включаются:
      - служебные переменные OpenVPN (IV_*, UV_*, X509_*, trusted_*, untrusted_*, ifconfig_*, route_*, daemon_*, remote_*, local_)
      - некоторые одиночные ключи (proto, dev, script_type, time_unix, time_ascii, OPENVPN_INSTANCE)
      - переменные NICEVPN_*
    Пароли и прочую чувствительную инфу сюда класть не нужно.
    """
    allowed_prefixes = (
        "IV_",
        "UV_",
        "X509_",
        "tls_",
        "trusted_",
        "untrusted_",
        "ifconfig_",
        "route_",
        "daemon",
        "remote_",
        "local_",
        "proto_",
        "tun_",
        "link_",
    )
    allowed_exact = (
        "proto",
        "dev",
        "dev_type",
        "redirect_gateway",
        "config",
        "verb",
        "LC_CTYPE",
        "script_type",
        "time_unix",
        "time_ascii",
        "OPENVPN_INSTANCE",
    )
    allowed_custom_prefixes = ("NICEVPN_",)

    result = {}
    for key, value in os.environ.items():
        # Грубая защита от случайного логирования секретов,
        # если когда-нибудь появятся auth-user-pass-verify и т.п.
        lower = key.lower()
        if any(s in lower for s in ("password", "passwd", "secret", "token", "cookie")):
            continue
        if key in allowed_exact:
            result[key] = value
            continue
        if any(key.startswith(p) for p in allowed_prefixes):
            result[key] = value
            continue
        if any(key.startswith(p) for p in allowed_custom_prefixes):
            # В NICEVPN_* уже лежит только то, что ты сам туда кладёшь.
            result[key] = value
            continue
    return result


def build_session_section():
    """Секция session: данные о сессии/соединении."""
    common_name = os.environ.get("NICEVPN_COMMON_NAME") or os.environ.get("common_name")

    vpn_ip = (
        os.environ.get("NICEVPN_VPN_IP")
        or os.environ.get("ifconfig_pool_remote_ip")
        or os.environ.get("ifconfig_local")
    )

    session = {
        "common_name": common_name,
        "username": os.environ.get("NICEVPN_USERNAME") or os.environ.get("username"),
        "trusted_ip": os.environ.get("trusted_ip"),
        "trusted_port": parse_int(os.environ.get("trusted_port")),
        "untrusted_ip": os.environ.get("untrusted_ip"),
        "untrusted_port": parse_int(os.environ.get("untrusted_port")),
        "vpn_ip": vpn_ip,
        "vpn_ipv6": os.environ.get("ifconfig_pool_ipv6"),
    }
    return session


def build_client_section():
    """Секция client: характеристики клиента (OS, приложение, шифры и т.д.)."""
    iv_gui = os.environ.get("IV_GUI_VER", "")
    client_app = None
    client_app_ver = None
    if iv_gui:
        # обычно формат вида "de.blinkt.openvpn_0.7.61"
        if "_" in iv_gui:
            client_app, client_app_ver = iv_gui.split("_", 1)
        else:
            client_app = iv_gui

    client = {
        "os": os.environ.get("IV_PLAT"),
        "os_ver": os.environ.get("IV_VER"),
        "app": client_app,
        "app_ver": client_app_ver,
        "ciphers": os.environ.get("IV_CIPHERS"),
        "sso": os.environ.get("IV_SSO"),
        "hwaddr": os.environ.get("IV_HWADDR"),
        "uuid": os.environ.get("UV_UUID"),
        "mtu": parse_int(os.environ.get("IV_MTU")),
    }

    return client


def build_traffic_section():
    """Секция traffic: трафик и длительность сессии. На connect обычно пусто, на disconnect заполнено."""
    traffic = {
        "bytes_received": parse_int(os.environ.get("bytes_received")),
        "bytes_sent": parse_int(os.environ.get("bytes_sent")),
        "duration_sec": parse_int(os.environ.get("time_duration")),
        "packets_received": parse_int(os.environ.get("packets_received")),
        "packets_sent": parse_int(os.environ.get("packets_sent")),
    }
    return traffic


def build_auth_section():
    """Секция auth: метод, результат и дополнительные детали аутентификации."""
    method = os.environ.get("NICEVPN_AUTH_METHOD")
    if not method:
        # Простейшая эвристика: если есть username — предполагаем пароль, иначе X.509
        if os.environ.get("NICEVPN_USERNAME") or os.environ.get("username"):
            method = "password"
        else:
            method = "x509"

    auth = {
        "method": method,
        "result": os.environ.get("NICEVPN_AUTH_RESULT"),
        "reason": os.environ.get("NICEVPN_AUTH_REASON"),
        "mfa_used": parse_int(os.environ.get("NICEVPN_MFA_USED")),
        "mfa_ok": parse_int(os.environ.get("NICEVPN_MFA_OK")),
    }
    return auth


def build_groups_section():
    """Секция groups: роли и ipset'ы, которые определяются внешними скриптами."""
    groups = {
        "ipsets": split_csv_env("NICEVPN_IPSETS"),
        "roles": split_csv_env("NICEVPN_ROLES"),
    }
    return groups


def build_cert_section():
    """Секция cert: информация о сертификате клиента и его цепочке."""
    subject_cn = os.environ.get("X509_0_CN") or os.environ.get("common_name")
    issuer_cn = os.environ.get("X509_1_CN") or os.environ.get("X509_0_issuer")

    cert = {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "serial": os.environ.get("X509_0_serial"),
        "not_before": os.environ.get("X509_0_notBefore"),
        "not_after": os.environ.get("X509_0_notAfter"),
    }
    return cert


def build_event():
    """Собирает финальный объект события для логирования."""
    timestamp = get_timestamp()

    event_type = os.environ.get("NICEVPN_EVENT_TYPE")
    script_type = os.environ.get("script_type")

    if not event_type:
        # fallback на script_type, если тип явно не задан
        event_type = script_type or "unknown"

    # если вообще нет типа и нет ни одного интересного env — лучше промолчать
    env_filtered = safe_env()
    if event_type == "unknown" and not script_type and not env_filtered:
        # возвращаем None, чтобы вызывающий код понял "ничего не писать"
        return None, timestamp

    event_id = os.environ.get("NICEVPN_EVENT_ID") or str(uuid.uuid4())

    event = {
        "event_id": event_id,
        "logger_version": LOGGER_VERSION,
        "event_type": event_type,
        "timestamp": timestamp,
        "script_type": script_type,
        "openvpn_instance": os.environ.get("OPENVPN_INSTANCE"),
        "source": "openvpn-hook",
        "session": build_session_section(),
        "client": build_client_section(),
        "traffic": build_traffic_section(),
        "auth": build_auth_section(),
        "groups": build_groups_section(),
        "cert": build_cert_section(),
        "env": env_filtered,
    }

    return event, timestamp


def fetch_geo_info(ip):
    """
    Получает информацию о внешнем IP из geo-сервиса.
    Возвращает dict или None при ошибке.
    """
    if not ip:
        return None

    lookup_url = f"http://95.165.14.90:9000/api/lookup?ip={urllib.parse.quote(ip)}"
    try:
        with urllib.request.urlopen(lookup_url, timeout=DEFAULT_API_TIMEOUT) as resp:
            if resp.status != 200:
                return None
            data = resp.read()
            return json.loads(data.decode("utf-8"))
    except Exception:
        debug = os.environ.get("NICEVPN_LOGGER_DEBUG") == "1"
        if debug:
            print(f"event-logger: geo lookup failed for {ip}", file=sys.stderr)
        return None


def write_event(event, event_ts):
    """
    Записывает событие в файл JSONL.
    Имя файла: <LOG_DIR>/<LOG_PREFIX>-YYYYMMDD.jsonl
    При создании файла устанавливаются права 0640.
    """
    log_dir = os.environ.get("NICEVPN_LOG_DIR", "/var/log/nicevpn")
    log_prefix = os.environ.get("NICEVPN_LOG_PREFIX", "events")

    # Используем локальное время для имени файла (проще визуально смотреть)
    date_str = time.strftime("%Y%m%d", time.localtime(event_ts))
    log_path = Path(log_dir) / f"{log_prefix}-{date_str}.jsonl"

    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Низкоуровневое открытие для контроля прав на новый файл
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    mode = 0o640

    fd = os.open(str(log_path), flags, mode)
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            # Компактный JSON без лишних пробелов
            json.dump(event, f, ensure_ascii=False, separators=(",", ":"))
            f.write("\n")
    finally:
        # fd закрывается контекстным менеджером, но на случай исключения до него
        try:
            os.close(fd)
        except OSError as e:
            if e.errno != errno.EBADF:
                raise


# ============================ ОТПРАВКА В API =================================


def compression_value_for_api(env_dict):
    """
    Восстановление значения compression в стиле старого client-event.sh.
    """
    for key in ("comp_lzo", "IV_COMP_STUB", "IV_COMP_STUBv2", "IV_LZO_STUB"):
        val = env_dict.get(key)
        if val:
            return val
    return ""

def map_event_type_for_api(event_type: str) -> str | None:
    # Нормализуем к тому, что ждёт Go-handler.
    if event_type == "session_connect":
        return "connect"
    if event_type == "session_disconnect":
        return "disconnect"

    # Новые типы — пишем в ту же таблицу client_events,
    # но без влияния на sessions (handler их просто вставит).
    if event_type in ("tls_verify", "ip_add", "ip_update"):
        return event_type

    # Остальное можно пока игнорировать
    return None

def build_api_payload(event):
    """
    Собирает payload для API в формате, совместимом с прежним client-event.sh.
    Возвращает dict или None, если это событие не нужно слать в API.
    """
    api_event_type = map_event_type_for_api(event.get("event_type", ""))
    if not api_event_type:
        return None

    env = event.get("env", {}) or {}
    session = event.get("session", {}) or {}
    client = event.get("client", {}) or {}
    traffic = event.get("traffic", {}) or {}
    auth = event.get("auth", {}) or {}
    geo = event.get("geo", {}) or {}

    payload = {
        "event_type": api_event_type,
        "event_time": str(event.get("timestamp", int(time.time()))),
        "vpn_instance_id": event.get("openvpn_instance") or env.get("OPENVPN_INSTANCE", ""),
        "common_name": session.get("common_name") or "",
        "username": session.get("username") or "",
        "auth_method": auth.get("method") or "",
        "mfa_used": str(auth.get("mfa_used") or 0),
        "mfa_ok": str(auth.get("mfa_ok") or 0),
        "trusted_ip": session.get("trusted_ip") or "",
        "trusted_port": str(session.get("trusted_port") or ""),
        "untrusted_ip": session.get("untrusted_ip") or "",
        "untrusted_port": str(session.get("untrusted_port") or ""),
        "vpn_ip": session.get("vpn_ip") or "",
        "vpn_ipv6": session.get("vpn_ipv6") or "",
        "proto": env.get("IV_PROTO") or env.get("proto", ""),
        "dev": env.get("dev", ""),
        "cipher": client.get("ciphers") or env.get("IV_CIPHERS", ""),
        "compression": compression_value_for_api(env),
        "device_os": client.get("os") or "",
        "device_os_ver": client.get("os_ver") or "",
        "device_type": env.get("IV_HWADDR", ""),
        "device_vendor": env.get("IV_HWADDR", ""),
        "device_model": env.get("IV_HWADDR", ""),
        "device_id": env.get("IV_HWADDR", ""),
        "client_app": client.get("app") or "",
        "client_app_ver": client.get("app_ver") or "",
        "dco_enabled": env.get("IV_DCO_ENABLED", "0"),
        "geo_country_code": geo.get("country_iso") or "",
        "geo_country_name": geo.get("country_name") or "",
        "geo_region": geo.get("region") or "",
        "geo_city": geo.get("city") or "",
        "geo_asn": geo.get("asn") or "",
        "geo_org": geo.get("as_org") or "",
        "geo_network": geo.get("network") or "",
        "geo_flag": geo.get("country_flag") or "",
        "geo_lat": geo.get("latitude") or "",
        "geo_lon": geo.get("longitude") or "",
        "bytes_received": str(traffic.get("bytes_received") or ""),
        "bytes_sent": str(traffic.get("bytes_sent") or ""),
        "packets_received": str(traffic.get("packets_received") or ""),
        "packets_sent": str(traffic.get("packets_sent") or ""),
        "duration_sec": str(traffic.get("duration_sec") or ""),
        # env_raw — это JSON со всем отфильтрованным окружением
        "env_raw": json.dumps(env, ensure_ascii=False, separators=(",", ":")),
    }

    return payload


def post_to_api(event):
    """
    Мягкая отправка события в API (если включено).
    Не ломает работу даже при ошибках, таймаут минимальный.
    """
    # Полностью отключить API-отправку
    if os.environ.get("NICEVPN_API_DISABLE") == "1":
        return

    api_url = (
        os.environ.get("NICEVPN_API_URL")
        or os.environ.get("API_URL")
        or DEFAULT_API_URL
    )
    if not api_url:
        return

    payload = build_api_payload(event)
    if not payload:
        return

    # Формат x-www-form-urlencoded, как в старом client-event.sh (curl --data-urlencode)
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(api_url, data=data, method="POST")

    # Таймаут берём из переменной, если задан, иначе DEFAULT_API_TIMEOUT
    timeout = DEFAULT_API_TIMEOUT
    timeout_env = os.environ.get("NICEVPN_API_TIMEOUT")
    if timeout_env:
        try:
            timeout = float(timeout_env)
        except ValueError:
            pass

    debug = os.environ.get("NICEVPN_LOGGER_DEBUG") == "1"

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Читаем чуть-чуть, чтобы запрос действительно ушёл
            _ = resp.read(1)
    except Exception as exc:
        # Любые ошибки API мягко игнорируем, только при debug пишем в stderr
        if debug:
            print(f"event-logger: API post failed: {exc}", file=sys.stderr)


# ============================ MAIN ===========================================


def main():
    try:
        event, ts = build_event()
        if event is None:
            # ничего логировать не надо
            return 0

        api_event_type = map_event_type_for_api(event.get("event_type", ""))
        if api_event_type == "connect":
            geo_ip = (event.get("session") or {}).get("trusted_ip")
            geo_info = fetch_geo_info(geo_ip)
            if geo_info:
                event["geo"] = geo_info

        write_event(event, ts)
        # Мягкая попытка отправить в API (если включено)
        post_to_api(event)
        return 0

    except Exception as exc:
        # По умолчанию логгер не должен ломать работу OpenVPN-хуков.
        debug = os.environ.get("NICEVPN_LOGGER_DEBUG") == "1"
        strict = os.environ.get("NICEVPN_LOGGER_STRICT") == "1"

        msg = f"event-logger: {exc}"
        print(msg, file=sys.stderr)

        if debug:
            import traceback

            traceback.print_exc()

        # Если нужен строгий режим — можно включить через NICEVPN_LOGGER_STRICT=1
        if strict:
            return 1
        return 0


if __name__ == "__main__":
    sys.exit(main())
