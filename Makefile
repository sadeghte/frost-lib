# Root Makefile

# Define the list of submodules
SUBMODULES := frost-ed25519 frost-secp256k1 frost-secp256k1-tr

# Detect OS to set optional flags (if submodules are set up to use them)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	# Mac OS specific flags (if needed)
	CARGO_FLAGS :=
else
	# Linux specific flags (if needed)
	CARGO_FLAGS :=
endif

# Default target
all: install

# Install target: iterate through each submodule and run `make install`
install:
	@for dir in $(SUBMODULES); \
	do \
		echo "Running 'make install' in $$dir..."; \
		$(MAKE) -C $$dir install || exit 1; \
	done

clean:
	@for dir in $(SUBMODULES); do \
		echo "Running 'make clean' in $$dir..."; \
		$(MAKE) -C $$dir clean || exit 1; \
	done

.PHONY: all install clean