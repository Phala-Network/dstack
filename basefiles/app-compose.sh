#!/bin/sh
tdxctl notify-host -e "boot.progress" -d "starting containers" || true

docker compose up --remove-orphans -d 2>/dev/null || true
chmod +x /usr/bin/containerd-shim-runc-v2
systemctl restart docker

if ! docker compose up --remove-orphans -d; then
    tdxctl notify-host -e "boot.error" -d "failed to start containers"
    exit 1
fi
tdxctl notify-host -e "boot.progress" -d "done" || true
