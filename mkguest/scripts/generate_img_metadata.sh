#!/bin/bash
DIST_DIR=$1
KERNEL=vmlinuz-${KERNEL_VERSION}
INITRD=initrd-${KERNEL_VERSION}.img
IMAGE=${QCOW_IMAGE_FILENAME}

ROOTFS_CPIO_PATH=$2
ROOTFS_HASH=$(sha256sum "$ROOTFS_CPIO_PATH" | awk '{print $1}')

mkdir -p $DIST_DIR
cat <<EOF > $DIST_DIR/metadata.json
{
    "cmdline": "root=/dev/vda1 ro console=tty1 console=ttyS0 boot=kmfs rootintegrity=$ROOTFS_INTEGRITY initimg=/dev/sr0",
    "kernel": "$KERNEL",
    "initrd": "$INITRD",
    "hda": "$IMAGE",
    "rootfs": "rootfs.iso",
    "rootfs_hash": "$ROOTFS_HASH",
    "bios": "/usr/share/qemu/OVMF.fd"
}
EOF