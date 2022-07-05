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

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
