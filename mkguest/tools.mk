THIS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CMD_TDXCTL := $(THIS_DIR)/../target/release/tdxctl
CMD_IOHASH := $(THIS_DIR)/../target/release/iohash

tdxctl: $(CMD_TDXCTL)
	cp $(CMD_TDXCTL) .

iohash: $(CMD_IOHASH)
	cp $(CMD_IOHASH) .

$(CMD_TDXCTL):
	cargo build --release -p tdxctl

$(CMD_IOHASH):
	cargo build --release -p iohash
