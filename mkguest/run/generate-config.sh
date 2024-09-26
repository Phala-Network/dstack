#!/bin/bash

# Check if rootfs path is provided
if [ $# -eq 0 ]; then
    echo "Error: Rootfs path not provided"
    echo "Usage: $0 <rootfs_path>"
    exit 1
fi

ROOTFS_PATH="$1"
ROOTFS_HASH=$(sha256sum "$ROOTFS_PATH" | awk '{print $1}')

KMS_URL=${KMS_URL:-https://kms.local:8043}
TPROXY_URL=${TPROXY_URL:-https://tproxy.local:8043}

# Generate JSON configuration
cat << EOF
{
    "rootfs_hash": "$ROOTFS_HASH",
    "kms_url": "${KMS_URL}",
    "tproxy_url": "${TPROXY_URL}"
}
EOF
