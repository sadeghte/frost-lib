# Root Makefile

# Define the list of submodules
SUBMODULES := frost-ed25519 frost-secp256k1 frost-secp256k1-tr  # Replace with your actual submodule names

# Default target to build and install all submodules
all: install

# Install target: iterate through each submodule and run `make install`
install:
	@for dir in $(SUBMODULES); do \
		echo "Running 'make install' in $$dir..."; \
		$(MAKE) -C $$dir install || exit 1; \
	done

# Optional: Clean all submodules
clean:
	@for dir in $(SUBMODULES); do \
		echo "Running 'make clean' in $$dir..."; \
		$(MAKE) -C $$dir clean || exit 1; \
	done

.PHONY: all install clean
