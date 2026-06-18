#!/bin/bash
# tells the shell to print every command to stdout
set -x

# drops the default Docker gateway route and directs all traffic to router node (ip 172.10.0.1)  
ip route del default
ip route add default via 172.10.0.1
# configures the system to use the google resolver
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

# stops the kernel from sending RST segments over TCP so that the hijacking experiment doesn't get interrupted  
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
