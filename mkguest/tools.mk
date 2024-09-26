THIS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CMD_TDXCTL := $(THIS_DIR)/../target/release/tdxctl
CMD_IOHASH := $(THIS_DIR)/../target/release/iohash
CMD_TAPPD := $(THIS_DIR)/../target/release/tappd

export CMD_TDXCTL
export CMD_IOHASH
export CMD_TAPPD

$(CMD_TDXCTL):
	cargo build --release -p tdxctl

$(CMD_IOHASH):
	cargo build --release -p iohash

$(CMD_TAPPD):
	cargo build --release -p tappd