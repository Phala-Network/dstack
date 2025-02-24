#!/bin/bash

USE_HEAD=${USE_HEAD:-yes}
TEEPOD_RPC=${TEEPOD_RPC}
CF_API_TOKEN=${CF_API_TOKEN}
CF_ZONE_ID=${CF_ZONE_ID}
SRV_DOMAIN=${SRV_DOMAIN}
PUBLIC_IP=${PUBLIC_IP}
TPROXY_APP_ID=${TPROXY_APP_ID}
ACME_STAGING=${ACME_STAGING:-yes}
SUBNET_INDEX=${SUBNET_INDEX:-0}
OS_IMAGE=${OS_IMAGE:-dstack-0.4.0}

BASE_PORT=6000
TPROXY_RPC_PORT=$((SUBNET_INDEX * 10 + BASE_PORT))
TPROXY_ADMIN_RPC_PORT=$((SUBNET_INDEX * 10 + BASE_PORT + 1))
TPROXY_SERVING_PORT=$((SUBNET_INDEX * 10 + BASE_PORT + 2))
TAPPD_PORT=$((SUBNET_INDEX * 10 + BASE_PORT + 3))
WG_PORT=$((SUBNET_INDEX * 10 + BASE_PORT))

MY_URL="https://${SRV_DOMAIN}:${TPROXY_RPC_PORT}"
if [ "$SUBNET_INDEX" -eq 0 ]; then
  BOOTNODE_URL="https://${SRV_DOMAIN}:$((10 + BASE_PORT))"
else
  BOOTNODE_URL="https://${SRV_DOMAIN}:${BASE_PORT}"
fi

required_env_vars=(
  "TEEPOD_RPC"
  "CF_API_TOKEN"
  "CF_ZONE_ID"
  "SRV_DOMAIN"
  "PUBLIC_IP"
  "TPROXY_APP_ID"
  "MY_URL"
  "BOOTNODE_URL"
)

for var in "${required_env_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Please set env variable $var"
    exit 1
  fi
done

CLI="../../teepod/src/teepod-cli.py --url $TEEPOD_RPC"

COMPOSE_TMP=$(mktemp)

if [ "$USE_HEAD" = "yes" ]; then
  CURRENT_REV=$(git rev-parse HEAD)
else
  CURRENT_REV=86290e4038aba067d784b088532c129d7ad4c828
fi
sed "s/git checkout TPROXY_REV/git checkout ${CURRENT_REV}/g" docker-compose.yaml > "$COMPOSE_TMP"
sed -i "s/\${ACME_STAGING}/$ACME_STAGING/g" "$COMPOSE_TMP"

echo "Docker compose file:"
cat "$COMPOSE_TMP"

$CLI compose \
    --docker-compose "$COMPOSE_TMP" \
    --name tproxy \
    --kms \
    --public-logs \
    --public-sysinfo \
    --output .app-compose.json

# Remove the temporary file as it is no longer needed
rm "$COMPOSE_TMP"

cat <<EOF > .env
CF_API_TOKEN=$CF_API_TOKEN
CF_ZONE_ID=$CF_ZONE_ID
SRV_DOMAIN=$SRV_DOMAIN
WG_ENDPOINT=$PUBLIC_IP:$WG_PORT
MY_URL=$MY_URL
BOOTNODE_URL=$BOOTNODE_URL
SUBNET_INDEX=$SUBNET_INDEX
EOF

echo "Configuration:"
echo "TEEPOD_RPC: $TEEPOD_RPC"
echo "SRV_DOMAIN: $SRV_DOMAIN"
echo "PUBLIC_IP: $PUBLIC_IP"
echo "TPROXY_APP_ID: $TPROXY_APP_ID"
echo "MY_URL: $MY_URL"
echo "BOOTNODE_URL: $BOOTNODE_URL"
echo "SUBNET_INDEX: $SUBNET_INDEX"
echo "WG_PORT: $WG_PORT"
echo "TPROXY_RPC_PORT: $TPROXY_RPC_PORT"
echo "TPROXY_ADMIN_RPC_PORT: $TPROXY_ADMIN_RPC_PORT"
echo "TPROXY_SERVING_PORT: $TPROXY_SERVING_PORT"
echo "TAPPD_PORT: $TAPPD_PORT"

echo "Deploying Tproxy to Teepod..."

$CLI deploy \
    --name tproxy \
    --app-id "$TPROXY_APP_ID" \
    --compose .app-compose.json \
    --env-file .env \
    --image $OS_IMAGE \
    --port tcp:0.0.0.0:$TPROXY_RPC_PORT:8000 \
    --port tcp:127.0.0.1:$TPROXY_ADMIN_RPC_PORT:8001 \
    --port tcp:0.0.0.0:$TPROXY_SERVING_PORT:443 \
    --port tcp:127.0.0.1:$TAPPD_PORT:8090 \
    --port udp:0.0.0.0:$WG_PORT:51820 \
    --vcpu 8 \
    --memory 8G \
    --disk 50G
