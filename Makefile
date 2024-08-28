build-docker-amd:
	BUILDKIT_PROGRESS=plain docker build -f amd.Dockerfile . -t sotazklabs/aptos-tools-amd64:mainnet

build-docker-arm:
	BUILDKIT_PROGRESS=plain docker build -f arm.Dockerfile . -t sotazklabs/aptos-tools-arm64:mainnet

manifest:
	docker manifest rm sotazklabs/aptos-tools:mainnet
	docker manifest create sotazklabs/aptos-tools:mainnet \
        sotazklabs/aptos-tools-amd64:mainnet \
        sotazklabs/aptos-tools-arm64:mainnet
	docker manifest push sotazklabs/aptos-tools:mainnet

test:
	cargo test --all-features

cargo-fmt:
	taplo fmt -o reorder_keys=true