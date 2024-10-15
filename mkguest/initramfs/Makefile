# Makefile for TDX Guest Initramfs Creation
include ../config.mk

# Variables
MKINITRAMFS := ./mkinitramfs
OUTPUT_INITRD := initrd-$(KERNEL_VERSION).img
INSTALL_DIR := $(shell pwd)/../dist

MOD_DIR = $(shell pwd)/../../mod-tdx-guest
TDX_KO = $(MOD_DIR)/tdx-guest.ko
MAKE_TDX_KO = make -C /lib/modules/$(KERNEL_VERSION)/build M=$(MOD_DIR)

export TDX_KO
export CMD_IOHASH
export CMD_TDXCTL

# Default target
all: $(OUTPUT_INITRD)

include ../tools.mk

# Create the TDX guest initramfs
$(OUTPUT_INITRD): $(MKINITRAMFS) $(TDX_KO) $(CMD_IOHASH) $(CMD_TDXCTL)
	$(MKINITRAMFS) -v -d config -o $(OUTPUT_INITRD) $(KERNEL_VERSION)

ko: $(TDX_KO)

$(TDX_KO):
	$(MAKE_TDX_KO)

# Install the initramfs
install: $(OUTPUT_INITRD)
	mkdir -p $(INSTALL_DIR)
	cp $(OUTPUT_INITRD) $(INSTALL_DIR)

# Clean up build artifacts
clean:
	rm -f *.img *.ko
	$(MAKE_TDX_KO) clean

.PHONY: all clean install ko
