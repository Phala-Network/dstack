
# Makefile for TDX Guest Initramfs Creation

include ../config.mk

# Variables
OUTPUT_IMAGE := rootfs.iso
IMAGE_PATH := ../image/$(QCOW_IMAGE_FILENAME)
ISO_ROOTDIR := isoroot
CPIO_IMAGE := $(ISO_ROOTDIR)/rootfs.cpio
INSTALL_DIR := $(shell pwd)/../dist

# Default target
all: $(OUTPUT_IMAGE)

# Create the TDX guest initramfs
$(OUTPUT_IMAGE): $(CPIO_IMAGE)
	mkisofs -o $(OUTPUT_IMAGE) --max-iso9660-filenames -input-charset utf-8 $(ISO_ROOTDIR)

$(CPIO_IMAGE): $(IMAGE_PATH)
	mkdir -p $(ISO_ROOTDIR)
	./mkcpio.sh $(IMAGE_PATH) $(CPIO_IMAGE)

$(IMAGE_PATH):
	$(MAKE) -C ../image

# Clean up build artifacts
clean:
	rm -f $(OUTPUT_IMAGE)
	rm -rf $(ISO_ROOTDIR)

install: $(OUTPUT_IMAGE)
	mkdir -p $(INSTALL_DIR)
	cp $(OUTPUT_IMAGE) $(INSTALL_DIR)

.PHONY: all clean install
