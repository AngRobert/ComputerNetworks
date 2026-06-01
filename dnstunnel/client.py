import socket
import os
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, TXT, QTYPE, RCODE

filename = input("Input the name of the file you want to request (including extension): ")

while not os.path.exists(f'files/{filename}'):
    print('ths file does not exist! try again.')
    fileame = input("Input the name of the file you want to request (including extension): ")

# ip of the server, obv
SERVER = '144.126.226.144'
PORT = 53
META_DOMAIN = f'meta.tunnel.{filename}.andrei12225.engineer'


# first, build the meta query
query = DNSRecord(q=DNSQuestion(META_DOMAIN), qtype=QTYPE.TXT).pack()

# intialize the socket and send the meta query
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(query, (SERVER, PORT))

data, address = s.recvfrom(1024)
response = DNSRecord.parse(data)

# value should be buc:x where x is the number of chunks
val = response.rr[0].rdata.data[0].decode()

print(val)