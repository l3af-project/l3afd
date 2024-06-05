FROM ubuntu:jammy@sha256:6d7b5d3317a71adb5e175640150e44b8b9a9401a7dd394f44840626aff9fa94d

ARG DEBIAN_FRONTEND=noninteractive

USER root

# Install necessary dependencies
RUN apt-get update && \
    apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    libbpf-dev \
    tzdata \
    cmake \
    zlib1g-dev \
    libevent-dev \
    vim \
    wget \
    curl \
    linux-tools-generic \
    net-tools \
    iproute2 \
    elfutils \
    libjson-c-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /srv/l3afd/
RUN mkdir -p /var/l3afd
RUN mkdir -p /var/log/l3af

COPY l3afd /root/l3afd
COPY l3afd.cfg /root/l3afd.cfg

ENTRYPOINT ["/root/l3afd", "--config", "/root/l3afd.cfg"]
