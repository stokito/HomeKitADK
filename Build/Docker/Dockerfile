# Build stage
FROM ubuntu:18.04

RUN echo ========== Install dependencies ========== \
  && chmod 1777 /tmp && apt-get update && apt-get install -y \
    clang \
    gdb \
    git \
    libavahi-compat-libdnssd-dev \
    libssl-dev \
    make \
    openssh-server \
    perl \
    unzip \
    wget \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build
