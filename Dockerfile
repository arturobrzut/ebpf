FROM ubuntu:latest AS build


RUN apt-get update && \
    apt-get install -y build-essential git cmake wget \
                       zlib1g-dev libevent-dev \
                       libelf-dev llvm \
                       clang libc6-dev-i386 golang-go

RUN mkdir /src && \
    git init

WORKDIR /src

RUN wget https://github.com/libbpf/bpftool/releases/download/v7.2.0/bpftool-v7.2.0-amd64.tar.gz && \
    tar -xvf bpftool-v7.2.0-amd64.tar.gz && \
    chmod 755 bpftool

# Link asm/byteorder.h into eBPF
RUN ln -s /usr/include/x86_64-linux-gnu/asm/ /usr/include/asm

# Build libbpf as a static lib
RUN git clone https://github.com/arturobrzut/libbpf-bootstrap.git && \
    cd libbpf-bootstrap && \
    git submodule update --init --recursive

RUN cd libbpf-bootstrap/libbpf/src && \
    make BUILD_STATIC_ONLY=y && \
    make install BUILD_STATIC_ONLY=y LIBDIR=/usr/lib/x86_64-linux-gnu/

# Clones the linux kernel repo and use the latest linux kernel source BPF headers 
RUN git clone --depth 1 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git && \
    cp linux/include/uapi/linux/bpf* /usr/include/linux/

RUN ls -l /sys/kernel/btf/vmlinux
RUN /src/bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
RUN ls -l vmlinux.h
RUN ls -l /src/libbpf-bootstrap/vmlinux/vmlinux.h
RUN cp vmlinux.h /src/libbpf-bootstrap/vmlinux/vmlinux.h


COPY * /src/
RUN go mod download github.com/aquasecurity/libbpfgo
RUN make all



FROM ubuntu:latest
RUN apt-get update
WORKDIR /src
COPY --from=build /src/main-static /src/main-static
COPY --from=build /src/main.bpf.o /src/main.bpf.o
COPY --from=build /src/bpftool /src/bpftool

