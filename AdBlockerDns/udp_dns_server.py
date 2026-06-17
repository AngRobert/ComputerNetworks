from scapy.all import *
from recursive_resolver import *

def send_response(dns_answer, packet, adresa_sursa, simple_udp):

    if dns_answer.rcode != 0: #eroare
        response_rcode = dns_answer.rcode
        answer_better = []
        aa_real = 0

    else:
        response_rcode = 0
        aa_real = 0

        if dns_answer.an == []:
            answer_better = []
        else:
            answer_better = dns_answer.an 

        if packet.qd.type == RecordType.CNAME.value:
            answer_better = dns_answer.ns


    dns_response = DNS(
                      id = packet[DNS].id, # DNS replies must have the same ID as requests
                      tc = 0, # fara trunchiere lol
                      qr = 1,              # 1 for response, 0 for query 
                      aa = aa_real,              # Authoritative Answer
                      rcode = response_rcode,           # 0, nicio eroare http://www.networksorcery.com/enp/protocol/dns.htm#Rcode,%20Return%20code
                      qd = packet.qd,      # request-ul original
                      an = answer_better)     # obiectul de reply

    print('response:')
    print (dns_response.summary())

    simple_udp.sendto(bytes(dns_response), adresa_sursa,)

"""
simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.bind(('0.0.0.0', 53))
"""

#ar trebui sa ascultam pe ipv6 ca sa nu ne mai dea request error la dig

simple_udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0) # ca sa accepte si pe ipv4
simple_udp.bind(('::', 53))

adDict = {}

with open("./adresses.txt", "r") as ads:
    for line in ads:
        if line[0] != '#':
            address, name = line.strip().split(" ")
            name = name + "." ##dns cauta cu . la sfarsit
            adDict[name] = address

cache = {}

while True:
    try:
        request, adresa_sursa = simple_udp.recvfrom(65535)
        print(adresa_sursa)
        
        #ip, port, chestie, chestie2 = adresa_sursa

        #daca adresa e ipv4 mapat pe ipv6, trebiue sa schimb ca sa pot trimite
        # chestiile sunt flowinfo si scopeid, habar nu am ce fac(inca)
        """
        if ip.startswith("::ffff:"):
            ip = ip.replace("::ffff:", "")
            

        adresa_sursa = (ip, port, chestie, chestie2)
        """

        # converitm payload-ul in pachet scapy
        packet = DNS(request)
        if not packet or not packet.haslayer(DNS): 
            dns_response = DNS(
                              id = packet[DNS].id, # DNS replies must have the same ID as requests
                              tc = 0, # fara trunchiere lol
                              qr = 1,              # 1 for response, 0 for query 
                              aa = 0,              # Authoritative Answer
                              rcode = 0,           # 0, nicio eroare http://www.networksorcery.com/enp/protocol/dns.htm#Rcode,%20Return%20code
                              qd = packet.qd,      # request-ul original
                              an = answer_better)     # obiectul de reply
            

        dns = packet.getlayer(DNS)

        an = dns.an if dns.an else []
        ns = dns.ns if dns.ns else []
        ar = dns.ar if dns.ar else [] 

        if dns is not None and dns.opcode == 0: # dns QUERY
            print ("got: ")
            print (packet.summary())

            questionURL = dns.qd.qname.decode('utf-8') ##poate schimbi din dict in lista? oare e mai rapid search-ul?
            #print(questionURL) ## aici e site-ul cautat

            ##daca site-ul e in reclame, return 0.0.0.0, altfel, cauta in chache, altfel, recursive query
            if questionURL in adDict:
                if dns.qd.qtype == RecordType.AAAA.value:
                    r_type = 28
                    r_data = "0:0:0:0:0:0:0:0" #nu mergea cu "::"
                else:
                    r_type = 1
                    r_data = "0.0.0.0"

                dns_answer = DNSRR(      # DNS Reply
                   rrname=dns.qd.qname, # for question
                   ttl=330,             # DNS entry Time to Live
                   type=r_type,            
                   rclass="IN",
                   rdata=r_data)     # found at IP: 1.1.1.1 :)

                send_response(dns_answer, packet, adresa_sursa, simple_udp)

            elif (questionURL, dns.qd.qtype) in cache:
                dns_answer = DNSRR(      # DNS Reply
                   rrname=dns.qd.qname, # for question
                   ttl=330,             # DNS entry Time to Live
                   type=dns.qd.qtype,
                   rclass="IN",
                   rdata=cache[(questionURL, dns.qd.qtype)])

                send_response(dns_answer, packet, adresa_sursa, simple_udp)

            else:
                resp = recursiveResolver(dns, dns.qd.qtype)

                send_response(resp, packet, adresa_sursa, simple_udp) # o sa trimita oricum cod de eroare daca e eroare

                if resp.rcode == 0:
                    if resp.an != []:
                        print("lululu:",resp.an) # nu pare sa ne dea adresa ip, poate trebuie sa caut din nou?
                                               # acum merge :)
                if resp.an != []:
                    for answer in resp.an:
                        if answer.type == RecordType.A.value or answer.type == RecordType.AAAA.value:
                            if len(cache) <= 1000: 
                                print(answer)
                                cached_response = answer 
                                cache[(questionURL, dns.qd.qtype)] = cached_response.rdata
                            else:
                                first_key = next(iter(cache))
                                cache.pop(first_key) #cache-ul e un fifo, nu am zis ca e un chache eficient, dar functioneaza
                                cache[(questionURL, dns.qd.qtype)] = answer.rdata
    except Exception as e: # ca sa nu se mai inchida script-ul la erori
            print('response:')
            print(e)

simple_udp.close()


