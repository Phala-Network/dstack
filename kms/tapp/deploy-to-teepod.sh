#!/bin/bash

USE_HEAD=${USE_HEAD:-yes}
TEEPOD_RPC=${TEEPOD_RPC}
OS_IMAGE=${OS_IMAGE:-dstack-0.4.0}
KMS_CONTRACT_ADDR=${KMS_CONTRACT_ADDR:-0x59E4a36B01a87fD9D1A4C12377253FE9a7b018Ba}
KMS_RPC_PORT=${KMS_RPC_PORT:-9201}
ETH_RPC_URL=${ETH_RPC_URL:-https://rpc.phala.network}

required_env_vars=(
  "TEEPOD_RPC"
  "KMS_RPC_PORT"
  "KMS_CONTRACT_ADDR"
  "ETH_RPC_URL"
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
  GIT_REV=$(git rev-parse HEAD)
else
  GIT_REV=86290e4038aba067d784b088532c129d7ad4c828
fi

cp compose-dev.yaml "$COMPOSE_TMP"

subvar() {
    sed -i "s|\${$1}|${!1}|g" "$COMPOSE_TMP"
}

subvar ETH_RPC_URL
subvar KMS_CONTRACT_ADDR
subvar GIT_REV

echo "Docker compose file:"
cat "$COMPOSE_TMP"

if [ -t 0 ]; then
  # Only ask for confirmation if running in an interactive terminal
  read -p "Continue? [y/N] " -n 1 -r
  echo
  
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      echo "Deployment cancelled"
      exit 1
  fi
fi

$CLI compose \
    --docker-compose "$COMPOSE_TMP" \
    --name tproxy \
    --kms \
    --public-logs \
    --public-sysinfo \
    --output .app-compose.json

# Remove the temporary file as it is no longer needed
rm "$COMPOSE_TMP"

echo "Deploying KMS to Teepod..."

$CLI deploy \
    --name kms \
    --compose .app-compose.json \
    --image $OS_IMAGE \
    --port tcp:0.0.0.0:$KMS_RPC_PORT:8000 \
    --vcpu 8 \
    --memory 8G \
    --disk 50G
