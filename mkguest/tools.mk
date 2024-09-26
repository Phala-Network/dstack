THIS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CMD_TDXCTL := $(THIS_DIR)/../target/release/tdxctl
CMD_IOHASH := $(THIS_DIR)/../target/release/iohash

export CMD_TDXCTL
export CMD_IOHASH

$(CMD_TDXCTL):
	cargo build --release -p tdxctl

$(CMD_IOHASH):
	cargo build --release -p iohash
