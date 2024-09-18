#!/bin/bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
IMAGE_PATH=$(realpath $1)
OUTPUT_IMAGE=$(realpath $2)
QCOW_PART=${QCOW_PART:-1}

TMP_ROOTFS=${SCRIPT_DIR}/tmprootfs

umount_qcow2() {
    local target_dir=$1
    local nbd=$(findmnt -n -o SOURCE ${target_dir})
    if [ -n "${nbd}" ]; then
        local intermediate_dir=$(dirname ${nbd})
        echo "umount -l ${target_dir}"
        umount -l ${target_dir}
        sleep 0.5
        echo "umount -l ${intermediate_dir}"
        umount -l ${intermediate_dir}
        sleep 0.5
    else
        echo "No mount point found for ${target_dir}"
    fi
    rm -rf ${target_dir}
}

umount_qcow2 ${TMP_ROOTFS}

rm -rf ${TMP_ROOTFS}
mkdir -p ${TMP_ROOTFS}
trap "rm -rf ${TMP_ROOTFS}" EXIT INT TERM

echo "Mounting ${IMAGE_PATH} at ${TMP_ROOTFS}"
./qcow2fuse -o fakeroot -o ro -p ${QCOW_PART} ${IMAGE_PATH} ${TMP_ROOTFS}
trap "umount_qcow2 ${TMP_ROOTFS}" EXIT INT TERM

cd ${TMP_ROOTFS} && find . | cpio -o --format=newc > ${OUTPUT_IMAGE}
