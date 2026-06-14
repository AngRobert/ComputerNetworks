from scapy.all import *

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

def recursiveResolver(lookup_this):
    #alegem un root server
    root = '198.41.0.4'

    name = lookup_this.qd.qname.decode('utf-8')
    lookup_this.show()

    dns = DNS(aa=0, rcode=0, an=[])

    while(dns.an == []):

        #deschidem un port udp pt conexiunea cu serverul
        simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
        simple_udp.bind(('0.0.0.0', 6767))

        #construim un pachet ca in exemplul in rust
        """classscapy.layers.dns.DNS(_pkt, /, *, length=None, 
        id=0, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, ad=0,
        cd=0, rcode=0, qdcount=None, ancount=None, nscount=None,
        arcount=None, qd=[<DNSQR  |>], an=[], ns=[], ar=[])
        """
        """
        classscapy.layers.dns.DNSQR(_pkt, /, *, 
        qname=b'www.example.com.', qtype=1, unicastresponse=0, qclass=1)[source]
        """

        dns_question = DNSQR(qname=lookup_this.qd.qname)

        dns = DNS(id=6767, qr=0, aa=0, rd=1, rcode=0, qdcount=1, qd=dns_question)
        simple_udp.sendto(bytes(dns), (root, 53))

        response, address = simple_udp.recvfrom(65535) 

        ##am adresa urmatorului in ar.rdata, daca e ultimul raspuns e in as, pot sa verific aa ca sa vad daca e rasp autoritativ

        pack = DNS(response)

        simple_udp.close()
        dns = pack.getlayer(DNS)

        dns.show()

        #print(dns.ar[1].rdata) type e 28 pt ipv6

        if dns.an != []:
            return dns

        i = 0
        while dns.ar[i].type == 28:
            i = i + 1

        root = dns.ar[i].rdata 

    return dns

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
        print(questionURL) ## aici e site-ul cautat

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

        dns_response = DNS(
                          id = packet[DNS].id, # DNS replies must have the same ID as requests
                          qr = 1,              # 1 for response, 0 for query 
                          aa = 1,              # Authoritative Answer
                          rcode = 0,           # 0, nicio eroare http://www.networksorcery.com/enp/protocol/dns.htm#Rcode,%20Return%20code
                          qd = packet.qd,      # request-ul original
                          an = dns_answer)     # obiectul de reply
        print('response:')
        print (dns_response.summary())

        simple_udp.sendto(bytes(dns_response), adresa_sursa)



simple_udp.close()
