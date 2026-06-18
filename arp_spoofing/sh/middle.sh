#!/bin/bash
set -x
ip route del default
ip route add default via 198.10.0.1 # tells all external traffic to go through the router
ip route add 172.10.0.0/16 via 198.10.0.1 # tells all traffic that should go to 172.10.0.0 (client) to go through the router
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# ensures routing is maintained 
iptables -t nat -A POSTROUTING -j MASQUERADE 
