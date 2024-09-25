#!/bin/bash
DIST_DIR=$1
KERNEL=vmlinuz-${KERNEL_VERSION}
INITRD=initrd-${KERNEL_VERSION}.img
IMAGE=${QCOW_IMAGE_FILENAME}

mkdir -p $DIST_DIR
cat <<EOF > $DIST_DIR/metadata.json
{
    "cmdline": "root=/dev/vda1 ro console=tty1 console=ttyS0 boot=kmfs rootintegrity=hmac-sha256 initimg=/dev/sr0",
    "kernel": "$KERNEL",
    "initrd": "$INITRD",
    "hda": "$IMAGE",
    "rootfs": "rootfs.iso",
    "bios": "/usr/share/qemu/OVMF.fd"
}
EOF