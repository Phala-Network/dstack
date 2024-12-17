#!/bin/sh

tdxctl notify-host -e "boot.progress" -d "pulling images" || true
if ! docker compose pull; then
    tdxctl notify-host -e "boot.error" -d "failed to pull images"
    exit 1
fi

tdxctl notify-host -e "boot.progress" -d "starting containers" || true
if ! docker compose up -d; then
    tdxctl notify-host -e "boot.error" -d "failed to start containers"
    exit 1
fi

tdxctl notify-host -e "boot.progress" -d "containers started" || true
