#!/bin/bash

CONFIG_PATH="/etc/tproxy/tproxy.toml"

if [ -f "$CONFIG_PATH" ]; then
    echo "Configuration file already exists: $CONFIG_PATH"
    exit 0
fi

mkdir -p /etc/tproxy/
mkdir -p /etc/wireguard/

# Generate WireGuard keys directly in memory
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)

# Create tproxy.toml configuration
cat > $CONFIG_PATH << EOF
keep_alive = 10
log_level = "info"
port = 8010

[core]
kms_url = ""
state_path = "/data/tproxy-state.json"
set_ulimit = true
tls_domain = ""

[core.certbot]
workdir = "/etc/certbot"

[core.wg]
public_key = "${PUBLIC_KEY}"
private_key = "${PRIVATE_KEY}"
ip = "10.0.0.1"
listen_port = 51820
client_ip_range = "10.0.0.0/24"
config_path = "/etc/wireguard/wg-tproxy.conf"
interface = "wg-tproxy"
endpoint = "${WG_ENDPOINT}"

[core.proxy]
cert_chain = "/etc/rproxy/certs/cert.pem"
cert_key = "/etc/rproxy/certs/key.pem"
base_domain = "app.localhost"
listen_addr = "0.0.0.0"
listen_port = 8443
tappd_port = 8090
buffer_size = 8192
connect_top_n = 3

[core.proxy.timeouts]
connect = "5s"
handshake = "5s"
cache_top_n = "30s"
data_timeout_enabled = true
idle = "10m"
write = "5s"
shutdown = "5s"
total = "5h"

[core.recycle]
enabled = true
interval = "5m"
timeout = "10h"
EOF

# Set appropriate permissions for the config file
chmod 600 $CONFIG_PATH

echo "Configuration files have been generated:"
echo "- tproxy.toml in $CONFIG_PATH"
