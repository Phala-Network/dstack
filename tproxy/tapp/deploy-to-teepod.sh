#!/bin/bash

TEEPOD_RPC=${TEEPOD_RPC}
CF_API_TOKEN=${CF_API_TOKEN}
CF_ZONE_ID=${CF_ZONE_ID}
SRV_DOMAIN=${SRV_DOMAIN}
PUBLIC_IP=${PUBLIC_IP}
TPROXY_APP_ID=${TPROXY_APP_ID}

TPROXY_RPC_PORT=9030
TPROXY_ADMIN_RPC_PORT=9031
TPROXY_SERVING_PORT=9033
TAPPD_PORT=9032
WG_PORT=9030

required_env_vars=(
  "TEEPOD_RPC"
  "CF_API_TOKEN"
  "CF_ZONE_ID"
  "SRV_DOMAIN"
  "PUBLIC_IP"
  "TPROXY_APP_ID"
)

for var in "${required_env_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Please set env variable $var"
    exit 1
  fi
done

CLI="../../teepod/src/teepod-cli.py --url $TEEPOD_RPC"

$CLI compose \
    --docker-compose docker-compose.yaml \
    --name tproxy \
    --kms \
    --public-logs \
    --public-sysinfo \
    --output .app-compose.json

cat <<EOF > .env
CF_API_TOKEN=$CF_API_TOKEN
CF_ZONE_ID=$CF_ZONE_ID
SRV_DOMAIN=$SRV_DOMAIN
WG_ENDPOINT=$PUBLIC_IP:$WG_PORT
EOF

$CLI deploy \
    --name tproxy \
    --app-id "$TPROXY_APP_ID" \
    --compose .app-compose.json \
    --env-file .env \
    --image dstack-0.4.0 \
    --port tcp:0.0.0.0:$TPROXY_RPC_PORT:8000 \
    --port tcp:127.0.0.1:$TPROXY_ADMIN_RPC_PORT:8001 \
    --port tcp:0.0.0.0:$TPROXY_SERVING_PORT:443 \
    --port tcp:127.0.0.1:$TAPPD_PORT:8090 \
    --port udp:0.0.0.0:$WG_PORT:51820 \
    --vcpu 8 \
    --memory 8G \
    --disk 50G
