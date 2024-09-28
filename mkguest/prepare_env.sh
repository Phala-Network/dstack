#!/bin/bash
set -e

SCRIPT_DIR=$(dirname $(realpath $0))
cd $SCRIPT_DIR

sudo ./scripts/prepare_env-sudo.sh

# Allow libvirt to access my files
sudo usermod -aG ${USER} libvirt-qemu

# install rustc if not installed
if ! rustc --version; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
fi

