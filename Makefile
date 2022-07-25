SHELL:=$(shell /usr/bin/env which bash)

.PHONY: install_tasks_rust_toolchain # Install the rust toolchain used by concrete-tasks
install_tasks_rust_toolchain:
	@./script/make_utils/install_rust_toolchain.sh \
	--version "$$(cat concrete-tasks/toolchain.txt)"

.PHONY: check_tasks_rust_toolchain # Check that the rust toolchain used by concrete-tasks is installed
check_tasks_rust_toolchain:
	@./script/make_utils/install_rust_toolchain.sh \
	--check \
	--version "$$(cat concrete-tasks/toolchain.txt)" || \
	if [[ "$$?" != "0" ]]; then \
		echo "Tasks toolchain is not installed. Please run: make install_tasks_rust_toolchain"; \
		echo ""; \
		exit 1; \
	fi

CSPRNG_CHECK_BUILD_DIR := $(CURDIR)/csprng_check_builds
NIST_BUILD_DIR := $(CSPRNG_CHECK_BUILD_DIR)/nist_sts

.PHONY: install_nist_test_tool # Install NIST statistical test suite tool used to check concrete-csprng behavior
install_nist_test_tool:
	mkdir -p $(NIST_BUILD_DIR)
	cd $(CSPRNG_CHECK_BUILD_DIR); \
	wget "https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip" && \
	echo "0238d2f1d26e120e3cc748ed2d4c674cdc636de37fc4027c76cc2a394fff9157  sts-2_1_2.zip" >> checksum && \
	sha256sum -c checksum && \
	unzip -q sts-2_1_2.zip;
	mv $(CSPRNG_CHECK_BUILD_DIR)/sts-2.1.2/sts-2.1.2 $(NIST_BUILD_DIR)
	rmdir $(CSPRNG_CHECK_BUILD_DIR)/sts-2.1.2
	$(MAKE) -C $(NIST_BUILD_DIR)/sts-2.1.2

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
