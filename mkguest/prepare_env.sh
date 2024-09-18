#!/bin/bash
set -e

SCRIPT_DIR=$(dirname $(realpath $0))
cd $SCRIPT_DIR

sudo ./scripts/prepare_env-sudo.sh
sudo chmod o+rx ~
sudo usermod -aG libvirt ${USER}

# install rustc if not installed
if ! rustc --version; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
fi

