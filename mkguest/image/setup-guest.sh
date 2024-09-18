#!/bin/bash

set -e

cd /tmp/tdx

add-apt-repository -y ppa:kobuk-team/tdx-release
add-apt-repository -y ppa:kobuk-team/tdx-attestation-release

apt install -y libtdx-attest-dev

curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh --version 27.1.2

systemctl daemon-reload
systemctl enable app-compose.service
