# SPDX-License-Identifier: GPL-2.0

KDIR := /lib/modules/$(shell uname -r)/build
INSTALL_MOD_PATH := $(shell pwd)/dist/

obj-m += tdx-guest.o
tdx-guest-objs := tdcall.o mod.o

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	make -C $(KDIR) M=$(PWD) modules_install INSTALL_MOD_PATH=$(INSTALL_MOD_PATH)
