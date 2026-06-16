from scapy.all import *
from enum import Enum

class RecordType(Enum):
    A = 1
    NS = 2
    CNAME = 5
    MX = 15
    AAAA = 28
    UNKNOWN = None


def recursiveResolver(dns_qd, question_type):
    #alegem un root server, de adaugat o alegere random
    root = '198.41.0.4'

    name = dns_qd.qname
    print(name, " numele de cautat")

    dns = DNS(aa=0, rcode=0, an=[])

    while(dns.an == [] and dns.rcode == 0): #iese daca avem raspuns sau eroare

        #deschidem un port udp pt conexiunea cu serverul
        simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
        simple_udp.bind(('0.0.0.0', 0)) #lasam os-ul sa decida portul


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

        dns_question = DNSQR(qname=name, qtype=question_type)

        dns = DNS(id=6767, qr=0, aa=0, rd=0, rcode=0, qdcount=1, qd=dns_question)
        simple_udp.sendto(bytes(dns), (root, 53))

        response, address = simple_udp.recvfrom(65535) 

        ##am adresa urmatorului in ar.rdata, daca e ultimul raspuns e in as, pot sa verific aa ca sa vad daca e rasp autoritativ

        pack = DNS(response)

        simple_udp.close()
        dns = pack.getlayer(DNS)

        record_type = dns.qd.qtype
        dns.show()

        #an e raspunsul final, ns e nameserver, ar e adresa nameserver-ului

        #print("-----------",dns.ar[2].type, dns.ar[2].rdata) #type e 28 pt ipv6

        
        if dns.an != []: # daca nu avem adresele aditionale
            return dns

        if dns.ns != [] and dns.ar == []:
            #ne trebuie adresa nameserver-ului
            attrfound = 0
            for nameserver in dns.ns:
                if not hasattr(nameserver, "rdata"):
                    dns.rcode = 1
                    return dns
                query = DNSQR(qname=nameserver.rdata, qtype=RecordType.A.value)
                resp = recursiveResolver(query, RecordType.A.value) #luam adresa serverului al carui nume il avem
                break

            if resp.rcode == 1:
                dns.rcode = 1
                return dns
            ##daca e soa, e raspuns negativ, daca e ns continui recursia
        
            root = resp.an.rdata

        else:
            found = 0
            for address in dns.ar:
                if address.type == RecordType.A.value:
                    found = 1
                    root = address.rdata
                    break

            if found == 0:
                dns.rcode = 1
                return dns
             
    return dns

