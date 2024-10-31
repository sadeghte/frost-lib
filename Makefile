
.PHONY: install build-addon clean

install: build-addon

build-addon:
	npx node-gyp configure build

clean:
	npx node-gyp clean
	rm -rf build
# rm -rf $(BUILD_DIR)