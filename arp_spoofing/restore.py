from scapy.all import sr, send
from scapy.layers.l2 import ARP
import sys

gateway_ip = "198.10.0.1"
target_ip = "198.10.0.2"

def get_mac(ip_address):
    # Given an IP, get the MAC.

    responses, _ = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=3, timeout=10, verbose=False)
    for _, r in responses:
        return r[ARP].hwsrc

    return None

def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    # Reverse ARP poisoning by sending correct ARP packets to both the gateway and the target.

    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5, verbose=False)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5, verbose=False)

print("Starting script to restore ARP...")
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

restore_network(gateway_ip, gateway_mac, target_ip, target_mac)