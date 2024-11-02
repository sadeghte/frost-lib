.PHONY: all install build-addon clean

all: build-addon

install: build-addon

build-addon:
	npx node-gyp configure build

clean:
	npx node-gyp clean
	rm -rf build