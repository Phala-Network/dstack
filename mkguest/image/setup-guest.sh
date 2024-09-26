#!/bin/bash
set -e
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh --version 27.1.2
systemctl daemon-reload
systemctl enable app-compose.service
