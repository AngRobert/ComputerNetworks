#!/bin/bash
set -x
ip route del default
ip route add default via 198.10.0.1
ip route add 172.10.0.0/16 via 198.10.0.1
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
iptables -t nat -A POSTROUTING -j MASQUERADE 
