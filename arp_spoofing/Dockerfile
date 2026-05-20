FROM ubuntu:20.04

USER root

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    iptables iproute2 iputils-ping tcpdump wget \
    curl net-tools arping python3 python3-pip \
    libnetfilter-queue-dev iperf3 moreutils \
    && rm -rf /var/lib/apt/lists/*

RUN pip install scapy