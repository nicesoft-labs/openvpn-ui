#!/usr/bin/env bash
# Example client event script for OpenVPN hooks.
# Install to /usr/libexec/nicevpn/client-event.sh and use from client-connect/disconnect.

set -euo pipefail
IFS=$'\n\t'

API_URL="${API_URL:-http://127.0.0.1:8080/internal/metrics/client-event}"
EVENT_TYPE="${1:-}"

case "$EVENT_TYPE" in
connect|disconnect)
        ;;
*)
        # Ignore unexpected hook invocations quietly to avoid breaking OpenVPN.
        exit 0
        ;;
esac

NOW_TS="$(date +%s)"

compression_value() {
  if [[ -n "${comp_lzo:-}" ]]; then
    echo "${comp_lzo}"
    return
  fi
  if [[ -n "${IV_COMP_STUB:-}" ]]; then
    echo "${IV_COMP_STUB}"
    return
  fi
  if [[ -n "${IV_COMP_STUBv2:-}" ]]; then
    echo "${IV_COMP_STUBv2}"
    return
  fi
  if [[ -n "${IV_LZO_STUB:-}" ]]; then
    echo "${IV_LZO_STUB}"
    return
  fi
  echo ""
}

build_env_json() {
  # lightweight env -> json to avoid extra dependencies
  local first=1
  printf '{'
  while IFS='=' read -r key value; do
    # skip empty keys
    [[ -z "$key" ]] && continue
    # escape quotes and backslashes
    value=${value//\\/\\\\}
    value=${value//"/\\"}
    key=${key//"/\\"}
    if [[ $first -eq 0 ]]; then
      printf ','
    fi
    printf '"%s":"%s"' "$key" "$value"
    first=0
  done < <(env)
  printf '}'
}

client_app_id="${IV_GUI_VER:-}"
client_app_ver=""
if [[ -n "$client_app_id" ]] && [[ "$client_app_id" == *"_"* ]]; then
  client_app_ver="${client_app_id#*_}"
  client_app_id="${client_app_id%%_*}"
fi

compression="$(compression_value)"
env_raw="$(build_env_json)"

curl --silent --show-error --fail --max-time 5 --connect-timeout 2 \
  --retry 2 --retry-delay 1 --retry-connrefused \
  -X POST "$API_URL" \
  --data-urlencode "event_type=${EVENT_TYPE}" \
  --data-urlencode "event_time=${NOW_TS}" \
  --data-urlencode "vpn_instance_id=${OPENVPN_INSTANCE:-}" \
  --data-urlencode "common_name=${common_name:-}" \
  --data-urlencode "username=${username:-}" \
  --data-urlencode "auth_method=${auth_method:-}" \
  --data-urlencode "mfa_used=${mfa_used:-0}" \
  --data-urlencode "mfa_ok=${mfa_ok:-0}" \
  --data-urlencode "trusted_ip=${trusted_ip:-}" \
  --data-urlencode "trusted_port=${trusted_port:-}" \
  --data-urlencode "untrusted_ip=${untrusted_ip:-}" \
  --data-urlencode "untrusted_port=${untrusted_port:-}" \
  --data-urlencode "vpn_ip=${ifconfig_pool_remote_ip:-}" \
  --data-urlencode "vpn_ipv6=${ifconfig_pool_ipv6:-}" \
  --data-urlencode "proto=${proto:-}" \
  --data-urlencode "dev=${dev:-}" \
  --data-urlencode "cipher=${cipher:-}" \
  --data-urlencode "compression=${compression}" \
  --data-urlencode "device_os=${IV_PLAT:-}" \
  --data-urlencode "device_os_ver=${IV_VER:-}" \
  --data-urlencode "device_type=${IV_HWADDR:-}" \
  --data-urlencode "device_vendor=${IV_HWADDR:-}" \
  --data-urlencode "device_model=${IV_HWADDR:-}" \
  --data-urlencode "device_id=${IV_HWADDR:-}" \
  --data-urlencode "client_app=${client_app_id}" \
  --data-urlencode "client_app_ver=${client_app_ver}" \
  --data-urlencode "dco_enabled=${IV_DCO_ENABLED:-0}" \
  --data-urlencode "bytes_received=${bytes_received:-}" \
  --data-urlencode "bytes_sent=${bytes_sent:-}" \
  --data-urlencode "packets_received=${packets_received:-}" \
  --data-urlencode "packets_sent=${packets_sent:-}" \
  --data-urlencode "duration_sec=${time_duration:-}" \
  --data-urlencode "env_raw=${env_raw}" \
  >/dev/null 2>&1 || true
