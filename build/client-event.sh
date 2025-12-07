#!/bin/bash
# Example client event script for OpenVPN hooks.
# Install to /usr/libexec/nicevpn/client-event.sh and use from client-connect/disconnect.

EVENT_TYPE="$1"
API_URL="http://127.0.0.1:8080/internal/metrics/client-event"

NOW_TS=$(date +%s)

curl -sS -X POST "$API_URL" \
  --data-urlencode "event_type=${EVENT_TYPE}" \
  --data-urlencode "event_time=${NOW_TS}" \
  --data-urlencode "common_name=${common_name}" \
  --data-urlencode "username=${username}" \
  --data-urlencode "trusted_ip=${trusted_ip}" \
  --data-urlencode "trusted_port=${trusted_port}" \
  --data-urlencode "untrusted_ip=${untrusted_ip}" \
  --data-urlencode "untrusted_port=${untrusted_port}" \
  --data-urlencode "vpn_ip=${ifconfig_pool_remote_ip}" \
  --data-urlencode "vpn_ipv6=${ifconfig_pool_ipv6}" \
  --data-urlencode "proto=${proto}" \
  --data-urlencode "dev=${dev}" \
  --data-urlencode "cipher=${cipher}" \
  --data-urlencode "compression=${comp_lzo}" \
  --data-urlencode "device_os=${IV_PLAT}" \
  --data-urlencode "device_os_ver=${IV_VER}" \
  --data-urlencode "client_app=${IV_GUI_VER}" \
  --data-urlencode "bytes_received=${bytes_received}" \
  --data-urlencode "bytes_sent=${bytes_sent}" \
  --data-urlencode "packets_received=${packets_received}" \
  --data-urlencode "packets_sent=${packets_sent}" \
  --data-urlencode "duration_sec=${time_duration}" \
  >/dev/null 2>&1 || exit 0
