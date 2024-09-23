# TDX Guest Components: Image, Rootfs, and Initramfs

include config.mk

DIST_DIR := $(shell pwd)/dist
COMPONENTS := image rootfs initramfs

export KERNEL_VERSION
export QCOW_IMAGE_FILENAME

.PHONY: all $(COMPONENTS) install $(addprefix dist-,$(COMPONENTS)) clean $(addprefix clean-,$(COMPONENTS))

all: $(COMPONENTS)

include tools.mk

$(COMPONENTS):
	$(MAKE) -C $@

define dist_component
dist-$(1): $(1)
	$(MAKE) -C $(1) install INSTALL_DIR=$(DIST_DIR)
endef

$(foreach component,$(COMPONENTS),$(eval $(call dist_component,$(component))))

dist-kernel:
	mkdir -p $(DIST_DIR)
	cp /boot/vmlinuz-$(KERNEL_VERSION) $(DIST_DIR)

dist: $(addprefix dist-,$(COMPONENTS)) dist-kernel
	./scripts/generate_img_metadata.sh $(DIST_DIR)

clean: $(addprefix clean-,$(COMPONENTS))

$(addprefix clean-,$(COMPONENTS)):
	$(MAKE) -C $(subst clean-,,$@) clean

prepare-kernel:
	apt install --yes linux-image-$(KERNEL_VERSION)
	chmod a+r /boot/vmlinuz-$(KERNEL_VERSION)

.PHONY: run clean
run:
	$(MAKE) -C run run

clean:
	$(MAKE) -C run clean
