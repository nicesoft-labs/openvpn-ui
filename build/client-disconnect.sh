#!/bin/bash
# Wrapper for OpenVPN client-disconnect hook. Installs to /usr/libexec/nicevpn/client-disconnect.sh

/usr/libexec/nicevpn/client-event.sh disconnect
