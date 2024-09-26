include ../config.mk

PWD=$(shell pwd)
BASE_IMAGE_PATH := $(PWD)/../dist/$(QCOW_IMAGE_FILENAME)

ROOTFS_CPIO_PATH := $(PWD)/../rootfs/isoroot/rootfs.cpio
CERTS_PATH := $(PWD)/../../certs

CERTS_TO_COPY := ca.cert tmp-ca.cert tmp-ca.key
CERTS_TO_COPY_PATHS := $(foreach cert, $(CERTS_TO_COPY), $(CERTS_PATH)/$(cert))

IMAGE_PATH := $(PWD)/vda.img
DEV_IMAGE_PATH := $(PWD)/dev-vda.img
CONFIG_DIR := $(PWD)/config
KERNEL_PATH := $(PWD)/../dist/vmlinuz-$(KERNEL_VERSION)
INITRD_PATH := $(PWD)/../dist/initrd-$(KERNEL_VERSION).img
ROOTFS_PATH := $(PWD)/../dist/rootfs.iso
SSH_PORT := 10086
TD := 0

export IMAGE_PATH
export CONFIG_DIR
export KERNEL_PATH
export INITRD_PATH
export ROOTFS_PATH
export SSH_PORT
export TD

$(DEV_IMAGE_PATH) $(IMAGE_PATH): $(BASE_IMAGE_PATH)
	qemu-img create -f qcow2 -o backing_file=$<,backing_fmt=qcow2 $@

$(BASE_IMAGE_PATH):
	$(MAKE) -C ../ dist-image

$(KERNEL_PATH):
	$(MAKE) -C ../ dist-kernel

$(INITRD_PATH):
	$(MAKE) -C ../ dist-initramfs

$(ROOTFS_PATH):
	$(MAKE) -C ../ dist-rootfs

.PHONY: run deps clean config

deps: $(KERNEL_PATH) $(INITRD_PATH) $(ROOTFS_PATH)

$(ROOTFS_CPIO_PATH):
	$(MAKE) -C ../ rootfs

$(CERTS_TO_COPY_PATHS):
	$(MAKE) -C ../../ certs

config: $(ROOTFS_CPIO_PATH) $(CERTS_TO_COPY_PATHS)
	mkdir -p $(CONFIG_DIR)/certs
	./generate-config.sh $(ROOTFS_CPIO_PATH) > $(CONFIG_DIR)/config.json
	cp docker-compose.yaml $(CONFIG_DIR)/
	cp $(CERTS_TO_COPY_PATHS) $(CONFIG_DIR)/certs/

run: deps $(IMAGE_PATH) config
	./run.sh

dev: deps $(DEV_IMAGE_PATH)
	IMAGE_PATH=$(DEV_IMAGE_PATH) BOOT=local RO9P=off ./run.sh

clean:
	rm -f $(IMAGE_PATH)
	rm -rf $(CONFIG_DIR)
