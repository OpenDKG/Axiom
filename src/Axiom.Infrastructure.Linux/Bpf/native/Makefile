# SPDX-License-Identifier: GPL-3.0-or-later
# Builds the Axiom BPF connect-time layer (docs/LINUX_EBPF.md §5):
#   out/axiom_connect.bpf.o   CO-RE object (clang -O2 -g -target bpf, BTF kept, DWARF stripped)
#   out/axiom-bpf-events      ring-buffer → NDJSON helper (links libbpf.so.1)
# Requirements: clang (≥ 14), llvm-strip, bpftool, libbpf-dev (≥ 1.0), a kernel with /sys/kernel/btf/vmlinux.
# `make install` copies both into the daemon publish tree (build/linux/axiomd/bpf/) so
# `axiomd --install-service` ships them under /usr/libexec/axiom/bpf/.
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
CC ?= cc
OUT ?= out
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
PUBLISH_DIR ?= $(abspath ../../../../build/linux/axiomd)/bpf
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/armv.*/arm/;s/ppc64le/powerpc/;s/riscv64/riscv/;s/s390x/s390/')

.PHONY: all clean install check-tools
all: check-tools $(OUT)/axiom_connect.bpf.o $(OUT)/axiom-bpf-events

check-tools:
	@command -v $(CLANG) >/dev/null || { echo "missing: $(CLANG) (apt install clang)"; exit 1; }
	@command -v $(BPFTOOL) >/dev/null || { echo "missing: $(BPFTOOL) (apt install linux-tools-common linux-tools-$$(uname -r))"; exit 1; }
	@test -r $(VMLINUX_BTF) || { echo "missing: $(VMLINUX_BTF) (kernel without BTF; CO-RE needs it)"; exit 1; }
	@test -r /usr/include/bpf/bpf_helpers.h || { echo "missing: /usr/include/bpf/bpf_helpers.h (apt install libbpf-dev)"; exit 1; }

vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(OUT):
	mkdir -p $(OUT)

$(OUT)/axiom_connect.bpf.o: axiom_connect.bpf.c axiom_bpf.h vmlinux.h | $(OUT)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Wno-unused-function -I. -c $< -o $@
	$(LLVM_STRIP) -g $@

$(OUT)/axiom-bpf-events: axiom-bpf-events.c axiom_bpf.h | $(OUT)
	$(CC) -O2 -Wall -Wextra -o $@ $< -lbpf

install: all
	mkdir -p $(PUBLISH_DIR)
	install -m 0644 $(OUT)/axiom_connect.bpf.o $(PUBLISH_DIR)/
	install -m 0755 $(OUT)/axiom-bpf-events $(PUBLISH_DIR)/

clean:
	rm -rf $(OUT) vmlinux.h
