#!/bin/sh
set -x
ip route add 80.96.21.96 via 198.10.0.1
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

