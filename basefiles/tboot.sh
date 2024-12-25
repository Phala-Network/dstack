#!/bin/sh
# Temporarily disable container auto-start
# This will be re-enabled later by app-compose.sh
chmod -x /usr/bin/containerd-shim-runc-v2

tdxctl tboot
