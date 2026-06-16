#!/bin/sh
set -x

# !!!
ip route add 80.96.21.96 via 198.10.0.1
# !!!
# IMPORTANT: this is needed to prevent packets going through the default gateway (for specifically the target website)
# so basically the server container will use the router container (which is poisoned) to access that ip
# for other websites, it will use the default gateway

echo "nameserver 8.8.8.8" >> /etc/resolv.conf

iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

