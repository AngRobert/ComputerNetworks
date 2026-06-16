from scapy.all import *

def recursiveResolver(lookup_this):
    #alegem un root server
    root = '198.41.0.4'

    name = lookup_this.qd.qname.decode('utf-8')
    lookup_this.show()

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

        dns_question = DNSQR(qname=lookup_this.qd.qname)

        dns = DNS(id=6767, qr=0, aa=0, rd=0, rcode=0, qdcount=1, qd=dns_question)
        simple_udp.sendto(bytes(dns), (root, 53))

        response, address = simple_udp.recvfrom(65535) 

        ##am adresa urmatorului in ar.rdata, daca e ultimul raspuns e in as, pot sa verific aa ca sa vad daca e rasp autoritativ

        pack = DNS(response)

        simple_udp.close()
        dns = pack.getlayer(DNS)

        #dns.show()

        #an e raspunsul final, ns e nameserver, ar e adresa nameserver-ului

        #print("-----------",dns.ar[2].type, dns.ar[2].rdata) #type e 28 pt ipv6

        
        if dns.ar == []: # daca nu avem adresele aditionale
            #ar trebui sa faci un query now cu un server din ns, shimbi tu mai in colo
            return dns


        root1 = 0 
        for addr in dns.ar:
            if addr.type == 1: #daca e A record
                root1 = addr.rdata
                break

        if root1 != 0:
            root = root1
        else
            #nu a mers, dar macar nu ar mai trebui sa dea crash
            return dns

    return dns

