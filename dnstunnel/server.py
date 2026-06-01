import socket, os, base64
from math import ceil
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, TXT, QTYPE, RCODE


# udp is always on port 53
PORT = 53
# 0.0.0.0 accepts all ip's associated with the server
SERVER = '0.0.0.0'
# number of bytes of each chunk ("bucata") we will be processing
# it is 180 because TXT can only hold 255 bytes, and when encoding in base64 a message will have a
# larger size by about 30% ==> a maximum size of 180 bytes + 30% = 240, which is < 255
BUCSIZE = 180
DOMAIN = 'tunnel.andrei12225.engineer'


# handles delivering the specific chunk of the file to the client
def handleBucataCommand(filename, nr_buc):
    if not os.path.exists(f'files/{filename}'):
        return False
    
    with open(f'files/{filename}', 'rb') as f:
        # go straight to the required chunk
        f.seek(nr_buc * BUCSIZE)
        buc = f.read(BUCSIZE)
        if not buc:
            return None
        return buc


# handles a client query about the size of the file requested
def handleMetaCommand(filename):
    if os.path.exists(f'files/{filename}'):
        size = os.path.getsize(f'files/{filename}')
        required_bucati = ceil(size / 180)
        return required_bucati
    
    return False


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

        # split the subdomain into the command and filename (eg. 'metadata', 'secret.txt', or 'buc2', 'secret.txt')
        command, filename = subd.split('.', 1)

        if command == "meta":
            if not handleMetaCommand(filename):
                response.header.rcode = RCODE.NXDOMAIN
                # .pack() is the opposite of .parse(), it packages the data to be put in the TXT response
                s.sendto(response.pack(), address)
                return 
            
            nr_bucati = handleMetaCommand(filename)
            text = f"chunks:{nr_bucati}"
        else:
            # command[3:] is because "buc" is 3 letters long, so we take everything after it
            nr_buc = int(command[3:])

            if not handleBucataCommand(filename, nr_buc):
                response.header.rcode = RCODE.NXDOMAIN
                s.sendto(response.pack(), address)
                return

            # buc is the actual chunk of the file
            buc = handleBucataCommand(filename, nr_buc)
            # encode it in base64 because those are the allowed characters for TXT records
            text = base64.b64encode(buc).decode()

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