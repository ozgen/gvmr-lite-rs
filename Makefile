.DEFAULT_GOAL := help

CARGO ?= cargo
CLI_ARGS ?= --help
SERVER_ARGS ?=

.PHONY: \
	help \
	check \
	check-core \
	check-server \
	check-cli \
	run-server \
	run-cli \
	test \
	nextest \
	cover \
	clippy \
	fmt \
	fmt-check \
	build \
	build-release \
	clean

help:
	@echo "gvmr-lite-rs Make targets:"
	@echo ""
	@echo "  make check          cargo check --workspace --all-targets"
	@echo "  make check-core     check gvmr-core"
	@echo "  make check-server   check gvmr-server"
	@echo "  make check-cli      check gvmr-cli"
	@echo ""
	@echo "  make run-server     run gvmr-server"
	@echo "  make run-cli        run gvmr-cli (default: --help)"
	@echo "  make run-cli CLI_ARGS='--xml report.xml --type native -o report.pdf'"
	@echo ""
	@echo "  make test           cargo test --workspace --all-targets"
	@echo "  make nextest        cargo nextest run --workspace --all-targets"
	@echo "  make cover          generate and open llvm-cov HTML coverage"
	@echo ""
	@echo "  make clippy         clippy with warnings denied"
	@echo "  make fmt            format workspace"
	@echo "  make fmt-check      check formatting"
	@echo ""
	@echo "  make build          build workspace"
	@echo "  make build-release  build workspace in release mode"
	@echo "  make clean          cargo clean"

check:
	$(CARGO) check \
		--workspace \
		--all-targets \
		--color always

check-core:
	$(CARGO) check \
		-p gvmr-core \
		--all-targets \
		--color always

check-server:
	$(CARGO) check \
		-p gvmr-server \
		--all-targets \
		--color always

check-cli:
	$(CARGO) check \
		-p gvmr-cli \
		--all-targets \
		--color always

run-server:
	$(CARGO) run \
		-p gvmr-server \
		--color always \
		-- $(SERVER_ARGS)

run-cli:
	$(CARGO) run \
		-p gvmr-cli \
		--color always \
		-- $(CLI_ARGS)

test:
	$(CARGO) test \
		--workspace \
		--all-targets \
		--color always

nextest:
	$(CARGO) nextest run \
		--workspace \
		--all-targets \
		--color always

cover:
	$(CARGO) llvm-cov \
		--workspace \
		--all-targets \
		--ignore-filename-regex '(_tests\.rs|tests/)' \
		--html \
		--open

clippy:
	$(CARGO) clippy \
		--workspace \
		--all-targets \
		--all-features \
		--color always \
		-- \
		-D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all --check

build:
	$(CARGO) build \
		--workspace \
		--color always

build-release:
	$(CARGO) build \
		--workspace \
		--release \
		--color always

clean:
	$(CARGO) clean