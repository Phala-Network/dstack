#!/bin/bash
set -e

BASE_DIR="/etc/tproxy"
CONFIG_PATH="$BASE_DIR/tproxy.toml"
CERTS_DIR="$BASE_DIR/certs"
WG_KEY_PATH="$BASE_DIR/wg.key"
KMS_URL=$(jq -j .kms_url /tapp/config.json)

if [ -f "$CONFIG_PATH" ]; then
    echo "Configuration file already exists: $CONFIG_PATH"
    # exit 0
fi

mkdir -p $BASE_DIR/
mkdir -p /etc/wireguard/

# Generate or load WireGuard keys
if [ -f "$WG_KEY_PATH" ]; then
    PRIVATE_KEY=$(cat "$WG_KEY_PATH")
else
    PRIVATE_KEY=$(wg genkey)
    echo "$PRIVATE_KEY" > "$WG_KEY_PATH"
    chmod 600 "$WG_KEY_PATH"  # Secure the private key file
fi
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)

# Create tproxy.toml configuration
cat > $CONFIG_PATH << EOF
keep_alive = 10
log_level = "info"
port = 8000

[tls]
key = "$CERTS_DIR/tproxy-rpc.key"
certs = "$CERTS_DIR/tproxy-rpc.cert"

[tls.mutual]
ca_certs = "$CERTS_DIR/tproxy-ca.cert"
mandatory = false

[admin]
enabled = true
port = 8001

[core]
state_path = "/data/tproxy-state.json"
set_ulimit = true
tls_domain = "tproxy.${SRV_DOMAIN}"

[core.certbot]
workdir = "/etc/certbot"

[core.wg]
public_key = "${PUBLIC_KEY}"
private_key = "${PRIVATE_KEY}"
ip = "10.4.0.1"
listen_port = 51820
client_ip_range = "10.4.0.0/22"
config_path = "/etc/wireguard/wg-tproxy.conf"
interface = "wg-tproxy"
endpoint = "${WG_ENDPOINT}"

[core.proxy]
cert_chain = "/etc/rproxy/certs/live/cert.pem"
cert_key = "/etc/rproxy/certs/live/key.pem"
base_domain = "${SRV_DOMAIN}"
listen_addr = "0.0.0.0"
listen_port = 8443
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

echo "Configuration file have been generated:"
echo "- tproxy.toml in $CONFIG_PATH"

exec "$@"