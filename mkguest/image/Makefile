# Makefile for TDX Guest Image Creation

include ../config.mk

export QCOW_IMAGE_FILENAME

# Variables
SCRIPT := ./create-td-image.sh
BUILD_DIR := build
OUTPUT_IMAGE := $(QCOW_IMAGE_FILENAME)
INSTALL_DIR := $(shell pwd)/../dist

# Default target
all: $(OUTPUT_IMAGE)

include ../tools.mk

# Create the TDX guest image
$(OUTPUT_IMAGE): $(SCRIPT) $(CMD_TDXCTL) $(CMD_TAPPD) app-compose.service
	$(SCRIPT) -o $(OUTPUT_IMAGE)

# Clean up build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(OUTPUT_IMAGE)

# Force recreation of the image
force:
	rm -f $(OUTPUT_IMAGE)
	$(MAKE) $(OUTPUT_IMAGE)

install: $(INSTALL_DIR)/$(OUTPUT_IMAGE)

$(INSTALL_DIR)/$(OUTPUT_IMAGE): $(OUTPUT_IMAGE)
	mkdir -p $(INSTALL_DIR)
	cp $(OUTPUT_IMAGE) $(INSTALL_DIR)

.PHONY: all clean force install
