#!/bin/bash

mkdir -p /etc/certbot/

# ACME_URL="https://acme-v02.api.letsencrypt.org/directory"
ACME_URL=https://acme-staging-v02.api.letsencrypt.org/directory

cat <<EOF > /etc/certbot/certbot.toml
# Path to the working directory
workdir = "/etc/rproxy/certs"
# ACME server URL
acme_url = "${ACME_URL}"
# Cloudflare API token
cf_api_token = "${CF_API_TOKEN}"
# Cloudflare zone ID
cf_zone_id = "${CF_ZONE_ID}"
# Auto set CAA record
auto_set_caa = true
# Domain to issue certificates for
domain = "${SRV_DOMAIN}"
# Renew interval in seconds
renew_interval = 3600
# Number of days before expiration to trigger renewal
renew_days_before = 10
# Renew timeout in seconds
renew_timeout = 120
# Command to run after renewal
renewed_hook = "curl -s http://localhost:8011/TproxyAdmin.Exit"
EOF

exec "$@"