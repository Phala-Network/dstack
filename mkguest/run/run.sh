#!/bin/bash

IMG=${IMAGE_PATH:-${PWD}/vda.img}

SSH_PORT=${SSH_PORT:-10086}
PROCESS_NAME=qemu

INITRD=${INITRD_PATH:-${PWD}/../dist/initrd.img}
KERNEL=${KERNEL_PATH:-${PWD}/../dist/vmlinuz}
CDROM=${ROOTFS_PATH:-${PWD}/../dist/rootfs.iso}
BOOT=${BOOT:-rafs}
INTEGRITY=${INTEGRITY:-}
CONFIG_DIR=${CONFIG_DIR:-${PWD}/config}
TD=${TD:-1}
TDVF_FIRMWARE=/usr/share/ovmf/OVMF.fd
RO9P=${RO9P:-on}

if [ "${INTEGRITY}" == "1" ]; then
	INTEGRITY="hmac-sha256"
fi

ARGS="${ARGS} -kernel ${KERNEL}"
ARGS="${ARGS} -initrd ${INITRD}"
CMDLINE="root=/dev/vda1 ro console=tty1 console=ttyS0 boot=${BOOT} rootintegrity=${INTEGRITY} initimg=/dev/sr0"

echo INITRD=${INITRD}
echo ARGS=${ARGS}
echo IMG=${IMG}
echo CMDLINE=${CMDLINE}
echo TD=${TD}

if [ "${TD}" == "1" ]; then
	MACHINE_ARGS=",confidential-guest-support=tdx,hpet=off"
	PROCESS_NAME=td
	TDX_ARGS="-device vhost-vsock-pci,guest-cid=4 -object tdx-guest,id=tdx"
	BIOS="-bios ${TDVF_FIRMWARE}"
fi

sleep 2

qemu-system-x86_64 \
		   -accel kvm \
		   -m 8G -smp 16 \
		   -name ${PROCESS_NAME},process=${PROCESS_NAME},debug-threads=on \
		   -cpu host \
		   -machine q35,kernel_irqchip=split${MACHINE_ARGS} \
		   ${BIOS} \
		   ${TDX_ARGS} \
		   -nographic \
		   -nodefaults \
		   -chardev stdio,id=ser0,signal=on -serial chardev:ser0 \
		   -device virtio-net-pci,netdev=nic0_td -netdev user,id=nic0_td,hostfwd=tcp::${SSH_PORT}-:22 \
		   -drive file=${IMG},if=none,id=virtio-disk0 -device virtio-blk-pci,drive=virtio-disk0 \
		   -cdrom ${CDROM} \
		   -virtfs local,path=${CONFIG_DIR},mount_tag=config,readonly=${RO9P},security_model=mapped,id=virtfs0 \
		   ${ARGS} \
		   -append "${CMDLINE}"
