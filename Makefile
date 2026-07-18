.PHONY: setup build release run test test-root lint fmt fmt-check ci clean

setup:
	bash tmp_setup.sh

build:
	cargo build

release:
	cargo build --release

root: build
	sudo RUST_LOG=info ./target/debug/boxed run --rootfs /tmp/minirootfs --memory 67108864 --hostname subhadeep --rootless /bin/sh 

nonroot: build
	RUST_LOG=info ./target/debug/boxed run --rootfs /tmp/minirootfs --hostname subhadeep --rootless /bin/sh 

test:
	cargo test

# Run tests that require root (namespace/cgroup/capability tests)
test-root:
	sudo cargo test -- --include-ignored

lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

# Full local CI gate: format + lint + test + release build
ci: fmt-check lint test release

clean:
	cargo clean
