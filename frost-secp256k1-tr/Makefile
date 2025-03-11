OS := $(shell uname)

.PHONY: install build-sl clean

install: build-sl

build-sl:
ifeq ($(OS), Darwin)
	cargo build --release --target x86_64-apple-darwin
else
	cargo build --release
endif

clean:
	npx node-gyp clean
	rm -rf build
	rm -rf target