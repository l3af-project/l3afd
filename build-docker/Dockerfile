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
RUN mkdir -p /usr/local/l3afd/latest 
RUN mkdir -p /usr/local/l3afd/v2.1.0/l3afd 

COPY l3afd /usr/local/l3afd/v2.1.0/l3afd/l3afd
COPY l3afd.cfg /usr/local/l3afd/v2.1.0/l3afd/l3afd.cfg
COPY start.sh /usr/local/l3afd/start.sh

RUN chmod +x /usr/local/l3afd/start.sh
RUN ln -s /usr/local/l3afd/v2.1.0/l3afd/l3afd /usr/local/l3afd/latest/l3afd 
RUN ln -s /usr/local/l3afd/v2.1.0/l3afd/l3afd.cfg /usr/local/l3afd/latest/l3afd.cfg

ENTRYPOINT ["/bin/bash","/usr/local/l3afd/start.sh"]
