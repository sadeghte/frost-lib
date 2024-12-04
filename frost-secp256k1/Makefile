.PHONY: install build-sl clean

install: build-sl

build-sl:
	cargo build --release

clean:
	npx node-gyp clean
	rm -rf build
	rm -rf target