build-docker:
	BUILDKIT_PROGRESS=plain docker build -t sotazklabs/aptos-tools:mainnet .

test:
	cargo test --all-features

cargo-fmt:
	taplo fmt -o reorder_keys=true