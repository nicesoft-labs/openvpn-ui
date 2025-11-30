#!/bin/bash
#VERSION 1.0
set -euo pipefail

APP_CONF="../openvpn-ui/conf/app.conf"
OPENVPN_DIR=$(grep -E "^OpenVpnPath\\s*=" "$APP_CONF" | cut -d= -f2 | tr -d '"' | tr -d '[:space:]')
CONFIG_FILE="$OPENVPN_DIR/server.conf"

if [[ -z "${OPENVPN_DIR}" ]]; then
  echo "OpenVPN path is not set in app.conf"
  exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "OpenVPN server config not found at $CONFIG_FILE"
  exit 1
fi

SUDO=""
if [[ $EUID -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    SUDO="sudo"
  else
    echo "Skipping iptables configuration: insufficient privileges and sudo is not available."
    exit 0
  fi
fi

if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables command is not available"
  exit 1
fi

dev_name=$(awk '/^dev[[:space:]]+/ {print $2; exit}' "$CONFIG_FILE")
proto=$(awk '/^proto[[:space:]]+/ {print $2; exit}' "$CONFIG_FILE")
port=$(awk '/^port[[:space:]]+/ {print $2; exit}' "$CONFIG_FILE")
server_line=$(awk '/^server[[:space:]]+/ {print $2" "$3; exit}' "$CONFIG_FILE")

[[ -z "$dev_name" ]] && dev_name="tun"
[[ -z "$proto" ]] && proto="udp"
[[ -z "$port" ]] && port="1194"

if [[ -z "$server_line" ]]; then
  echo "No server directive found in $CONFIG_FILE"
  exit 1
fi

read -r vpn_network vpn_mask <<<"$server_line"

mask_to_prefix() {
  local mask=$1
  local prefix=0
  local octet
  IFS=. read -r o1 o2 o3 o4 <<<"$mask"
  for octet in $o1 $o2 $o3 $o4; do
    case $octet in
      255) prefix=$((prefix + 8)) ;;
      254) prefix=$((prefix + 7)) ;;
      252) prefix=$((prefix + 6)) ;;
      248) prefix=$((prefix + 5)) ;;
      240) prefix=$((prefix + 4)) ;;
      224) prefix=$((prefix + 3)) ;;
      192) prefix=$((prefix + 2)) ;;
      128) prefix=$((prefix + 1)) ;;
      0) ;;
      *) echo "Unsupported netmask: $mask"; return 1 ;;
    esac
  done
  echo "$prefix"
}

prefix=$(mask_to_prefix "$vpn_mask")
if [[ -z "$prefix" ]]; then
  echo "Unable to calculate prefix for $vpn_mask"
  exit 1
fi

vpn_subnet="$vpn_network/$prefix"

default_iface=$(ip route show default 2>/dev/null | awk '/^default/ {print $5; exit}')
[[ -z "$default_iface" ]] && default_iface="eth0"

iptables_cmd() {
  $SUDO iptables "$@"
}

ensure_rule() {
  local table_args=()
  if [[ $1 == "-t" ]]; then
    table_args=("-t" "$2")
    shift 2
  fi
  local chain=$1; shift
  if ! iptables_cmd "${table_args[@]}" -C "$chain" "$@" 2>/dev/null; then
    iptables_cmd "${table_args[@]}" -A "$chain" "$@"
  fi
}

echo "Applying iptables rules (dev=${dev_name}+, iface=$default_iface, port=$port/$proto, subnet=$vpn_subnet)"

ensure_rule INPUT -p "$proto" --dport "$port" -j ACCEPT
ensure_rule INPUT -i "${dev_name}+" -j ACCEPT
ensure_rule FORWARD -i "${dev_name}+" -s "$vpn_subnet" -j ACCEPT
ensure_rule -t nat POSTROUTING -s "$vpn_subnet" -o "$default_iface" -j MASQUERADE

echo "iptables rules applied."
