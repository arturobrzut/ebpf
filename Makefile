BASEDIR = $(abspath ../../)

OUTPUT = /usr/lib/x86_64-linux-gnu/

LIBBPF_OBJ = /usr/lib/x86_64-linux-gnu/libbpf.a

CLANG = clang
CC = $(CLANG)
GO = go

ARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')
TARGET_ARCH := x86

CFLAGS = -g -O2 -Wall -fpie -I/src/libbpf-bootstrap/vmlinux/
LDFLAGS =

CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT)) -I$(abspath ../common)"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

CGO_CFLAGS_DYN = "-I. -I/usr/include/"
CGO_LDFLAGS_DYN = "-lelf -lz -lbpf"

MAIN = main

.PHONY: $(MAIN)
.PHONY: $(MAIN).go
.PHONY: $(MAIN).bpf.c

all: $(MAIN)-static



outputdir:
	$(MAKE) -C $(BASEDIR) outputdir

## test bpf dependency

$(MAIN).bpf.o: $(MAIN).bpf.c
	$(CLANG) $(CFLAGS) -target bpf -D__KERNEL__ -D__TARGET_ARCH_$(TARGET_ARCH)  -I$(OUTPUT) -I/src/libbpf-bootstrap/vmlinux/ -c $< -o $@

## test

.PHONY: $(MAIN)-static

$(MAIN)-static: $(MAIN).bpf.o
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(ARCH) \
		$(GO) build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		-o $(MAIN)-static ./$(MAIN).go


clean:
	rm -f *.o *-static *-dynamic
