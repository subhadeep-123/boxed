.PHONY: setup build run

setup:
	bash tmp_setup.sh

build:
	cargo build

run: build
	sudo RUST_LOG=info ./target/debug/boxed run \
		--rootfs /tmp/minirootfs --mem 67108864 /bin/sh
