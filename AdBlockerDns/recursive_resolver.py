from scapy.all import *
from enum import Enum

class RecordType(Enum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    MX = 15
    AAAA = 28
    UNKNOWN = None

def findIp(dns, visitedIp):
    ns = dns.ns if dns.ns else []
    ar = dns.ar if dns.ar else []
    if dns.ns == [] and dns.ar == []:
        return -1 #nu avem ce face

    if dns.ar != []:
        for elem in dns.ar:
            if elem.type == RecordType.A.value:
                return elem.rdata

    #numai cazul in care avem ns sau nu am gasit A in ar

    for nameserver in dns.ns:

        if not hasattr(nameserver, "rdata"):
            continue

        if namserver.rdata in visitedIp:
            contiune
        resp = recursiveResolver(nameserver.rdata, RecordType.A.value) #luam adresa serverului al carui nume il avem

        if resp.rcode != 0:
            return -1

        if resp.an != []:
            for answer in resp.an:
                if answer.type == RecordType.A.value:
                    return answer.rdata

    return -1

def recursiveResolver(dnsqname, question_type):
    #alegem un root server, de adaugat o alegere random
    root = '198.41.0.4'
    visitedIp = set()
    nextIp = root

    name = dnsqname
    print(name, " numele de cautat")

    dns = DNS(aa=0, rcode=0, an=[], qd = [])

    #deschidem un port udp pt conexiunea cu serverul
    simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    simple_udp.bind(('0.0.0.0', 0)) #lasam os-ul sa decida portul

    iterations = 0

    while(dns.an == [] and dns.rcode == 0 and iterations < 30): #iese daca avem raspuns sau eroare

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
        simple_udp.sendto(bytes(dns), (nextIp, 53))

        response, address = simple_udp.recvfrom(65535) 

        ##am adresa urmatorului in ar.rdata, daca e ultimul raspuns e in as, pot sa verific aa ca sa vad daca e rasp autoritativ

        pack = DNS(response)

        dns = pack.getlayer(DNS)

        record_type = dns.qd.qtype
        dns.show()

        #an e raspunsul final, ns e nameserver, ar e adresa nameserver-ului

        #print("-----------",dns.ar[2].type, dns.ar[2].rdata) #type e 28 pt ipv6

        if dns.rcode != 0: #eroare
            simple_udp.close()
            return dns

        if dns.an == []:
            if dns.ns != []:
                for nsname in dns.ns:
                    if nsname.type == RecordType.SOA.value: #nu e de gasit domeniul
                        simple_udp.close()
                        return dns
            
        if dns.an != []: # am raspuns si nu am eroare
            for answer in dns.an:
                if answer.type == RecordType.CNAME.value and question_type != RecordType.CNAME.value: #trebuie sa dam si adresa
                    simple_udp.close()
                    return recursiveResolver(answer.rdata, question_type)
                return dns

        
        nextIpMaybe = findIp(dns, visitedIp)

        if nextIpMaybe == -1 or nextIpMaybe == None:
            simple_udp.close()
            return dns #intoarcem ultimul raspuns valid

        if nextIpMaybe in visitedIp: #loop
            simple_udp.close()
            return dns

        nextIp = nextIpMaybe
        visitedIp.add(nextIp)
        iterations += 1
            

