#!/bin/sh
set -e

APP_COMPOSE_FILE=/tapp/app-compose.json

prepare_docker_compose() {
    local runner=$(jq -r '.runner' $APP_COMPOSE_FILE)
    if [ "$runner" = "docker-compose" ]; then
        jq -r .docker_compose_file $APP_COMPOSE_FILE > /tapp/docker-compose.yaml
    else
        echo "Unsupported runner: $runner"
        exit 1
    fi
}

setup_tproxy_net() {
    local FEATURES=$(jq -r '.features[]' $APP_COMPOSE_FILE)
    if ! echo "$FEATURES" | grep -q "tproxy-net"; then
        echo "tproxy is not enabled"
        return
    fi

    local CLIENT_PRIVATE_KEY=$(wg genkey)
    local CLIENT_PUBLIC_KEY=$(echo $CLIENT_PRIVATE_KEY | wg pubkey)

    local TPROXY_URL=$(jq -r '.tproxy_url' /tapp/config.json)

    curl ${TPROXY_URL}/prpc/Tproxy.RegisterCvm?json \
        --cacert /etc/tappd/ca.cert \
        --cert /etc/tappd/tls.cert \
        --key /etc/tappd/tls.key \
        -d"{\"client_public_key\":\"${CLIENT_PUBLIC_KEY}\"}" \
        -o /tmp/wginfo.json

    local CLIENT_IP=$(jq -r '.wg.client_ip' /tmp/wginfo.json)
    local SERVER_ENDPOINT=$(jq -r '.wg.server_endpoint' /tmp/wginfo.json)
    local SERVER_PUBLIC_KEY=$(jq -r '.wg.server_public_key' /tmp/wginfo.json)
    local SERVER_IP=$(jq -r '.wg.server_ip' /tmp/wginfo.json)

    echo "WG CLIENT_IP: ${CLIENT_IP}"
    echo "WG SERVER_ENDPOINT: ${SERVER_ENDPOINT}"
    echo "WG SERVER_PUBLIC_KEY: ${SERVER_PUBLIC_KEY}"
    echo "WG SERVER_IP: ${SERVER_IP}"

    rm -f /tmp/wginfo.json

    mkdir -p /etc/wireguard
    cat <<EOF > /etc/wireguard/wg0.conf
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_IP}/24

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
AllowedIPs = ${SERVER_IP}/24
Endpoint = ${SERVER_ENDPOINT}
PersistentKeepalive = 25
EOF
    wg-quick up wg0
}

prepare_certs() {
    mkdir -p /etc/tappd
    cp /tapp/certs/ca.cert /etc/tappd/ca.cert
    jq -r '.app_key' /tapp/appkeys.json > /etc/tappd/app-ca.key
    jq -r '.certificate_chain[]' /tapp/appkeys.json | awk 'NF {print $0 > "/etc/tappd/app-ca.cert"}'

    tdxctl gen-ra-cert \
        --ca-key /etc/tappd/app-ca.key \
        --ca-cert /etc/tappd/app-ca.cert \
        --cert-path /etc/tappd/tls.cert \
        --key-path /etc/tappd/tls.key

    cat /etc/tappd/app-ca.cert >> /etc/tappd/tls.cert
}

prepare_certs && \
    setup_tproxy_net && \
    prepare_docker_compose
