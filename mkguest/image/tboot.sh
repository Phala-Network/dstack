#!/bin/bash
set -e

CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo $CLIENT_PRIVATE_KEY | wg pubkey)

TPROXY_URL=$(jq -r '.tproxy_url' /tapp/config/config.json)

mkdir -p /etc/tappd
cp /tapp/config/certs/ca.cert /etc/tappd/ca.cert
jq -r '.app_key' /tapp/appkeys.json > /etc/tappd/app-ca.key
jq -r '.certificate_chain[]' /tapp/appkeys.json | awk 'NF {print $0 > "/etc/tappd/app-ca.cert"}'

tdxctl gen-ra-cert \
    --ca-key /etc/tappd/app-ca.key \
    --ca-cert /etc/tappd/app-ca.cert \
    --cert-path /etc/tappd/tls.cert \
    --key-path /etc/tappd/tls.key

cat /etc/tappd/app-ca.cert >> /etc/tappd/tls.cert

curl ${TPROXY_URL}/prpc/Tproxy.RegisterCvm?json \
    --cacert /etc/tappd/ca.cert \
    --cert /etc/tappd/tls.cert \
    --key /etc/tappd/tls.key \
    -d"{\"client_public_key\":\"${CLIENT_PUBLIC_KEY}\"}" \
    -o /tmp/wginfo.json

CLIENT_IP=$(jq -r '.client_ip' /tmp/wginfo.json)
SERVER_ENDPOINT=$(jq -r '.server_endpoint' /tmp/wginfo.json)
SERVER_PUBLIC_KEY=$(jq -r '.server_public_key' /tmp/wginfo.json)
SERVER_IP=$(jq -r '.server_ip' /tmp/wginfo.json)

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