from scapy.all import *
from recursive_resolver import recursiveResolver

simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.bind(('0.0.0.0', 53))

adDict = {}

with open("./adresses.txt", "r") as ads:
    for line in ads:
        if line[0] != '#':
            address, name = line.strip().split(" ")
            name = name + "." ##dns cauta cu . la sfarsit
            adDict[name] = address

cache = {}

try:
    while True:

        request, adresa_sursa = simple_udp.recvfrom(65535)
        print(adresa_sursa)
        # converitm payload-ul in pachet scapy
        packet = DNS(request)
        dns = packet.getlayer(DNS)

        if dns is not None and dns.opcode == 0: # dns QUERY
            print ("got: ")
            print (packet.summary())

            questionURL = dns.qd.qname.decode('utf-8') ##poate schimbi din dict in lista? oare e mai rapid search-ul?
            #print(questionURL) ## aici e site-ul cautat

            ##daca site-ul e in reclame, return 0.0.0.0, altfel, cauta in chache, altfel, recursive query
            if questionURL in adDict:
                dns_answer = DNSRR(      # DNS Reply
                   rrname=dns.qd.qname, # for question
                   ttl=330,             # DNS entry Time to Live
                   type="A",            
                   rclass="IN",
                   rdata='0.0.0.0')     # found at IP: 1.1.1.1 :)

            elif questionURL in cache:
                dns_answer = DNSRR(      # DNS Reply
                   rrname=dns.qd.qname, # for question
                   ttl=330,             # DNS entry Time to Live
                   type="A",            
                   rclass="IN",
                   rdata=cache[questionURL])
            else:
                resp = recursiveResolver(dns)
                print("lululu:",resp.an.rdata) # nu pare sa ne dea adresa ip, poate trebuie sa caut din nou?
                                               # acum merge :)
                dns_answer = resp.an
                if len(cache) <= 1000:
                    cache[questionURL] = resp.an.rdata
                else:
                    first_key = next(iter(cache))
                    cahce.pop(first_key) #cache-ul e un fifo, nu am zis ca e un chache eficient, dar functioneaza
                    cache[questionURL] = resp.an.rdata

            """
            dns_response = DNS(
                              id = packet[DNS].id, # DNS replies must have the same ID as requests
                              qr = 1,              # 1 for response, 0 for query 
                              aa = 1,              # Authoritative Answer
                              rcode = 0,           # 0, nicio eroare http://www.networksorcery.com/enp/protocol/dns.htm#Rcode,%20Return%20code
                              qd = packet.qd,      # request-ul original
                              an = dns_answer)     # obiectul de reply
                              """

            dns_response = resp
            dns_response.id = packet[DNS].id

            print('response:')
            print (dns_response.summary())

            simple_udp.sendto(bytes(dns_response), adresa_sursa)

    simple_udp.close()

except Exception as e: # ca sa nu se mai inchida script-ul la erori
    print(e)
