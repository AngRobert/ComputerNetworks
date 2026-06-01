import socket
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, TXT, QTYPE, RCODE


# udp is always on port 53
PORT = 53
# 0.0.0.0 accepts all ip's associated with the server
SERVER = '0.0.0.0'
DOMAIN = 'tunnel.andrei12225.engineer'

def handleQuery(data, address, s):
    try:
        request = DNSRecord.parse(data)
    except Exception as e:
        print("Exception occured when handling DNS Packet: ", e)
        return 

    # get the qname and qtype from the request, removing the trailing '.'
    qname = str(request.q.qname).rstrip(".")
    qtype = QTYPE[request.q.qtype]

    print(f"Got query from {address} with qname: {qname} and qtype: {qtype}")
    
    # initialize a reply entity to which we will add answers
    response = request.reply()

    # if it's a txt query from our tonneling domains, extract the subdomains
    if qtype == "TXT" and qname.endswith(DOMAIN):
        
        # get the subdomain from the qname, the -1 is there to keep account of the '.' before the domain name
        subd = qname[:len(qname) - len(DOMAIN) - 1]
        print(f"subdomain: {subd}")

        text = f"got:{subd}"

        # actually add the answer to the response
        response.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(text), ttl=0))
    else:
        # if it's not a txt query, it dont matter 
        response.header.rcode = RCODE.NXDOMAIN

    s.sendto(response.pack(), address)




# initialize the socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((SERVER, PORT))

print(f"Tunnel listening on {SERVER}:{PORT}")

try:
    while True:
        # we're recieving up to 1024 bytes
        data, address = s.recvfrom(1024)
        handleQuery(data, address, s)

except KeyboardInterrupt:
    print("done")
    s.close()