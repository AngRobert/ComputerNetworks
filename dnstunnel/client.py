import hashlib
import socket
from time import sleep
import base64
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, TXT, QTYPE, RCODE

filename = input("Input the name of the file you want to request (including extension): ")


# ip of the server, obv
SERVER = '144.126.226.144'
PORT = 53
META_DOMAIN = f'meta.{filename}.tunnel.andrei12225.engineer'

# we will use this to check against the md5 checksum we will get when we ask for metadata
def get_md5(filename):
    hash = hashlib.md5()
    with open(filename, 'rb') as f:
        # read the file in bucati of 8192 so we dont run out of memory in the case of massive files
        while buc := f.read(8192):
            hash.update(buc)
    return hash.hexdigest()


# first, build the meta query
query = DNSRecord(q=DNSQuestion(META_DOMAIN, QTYPE.TXT)).pack()

# intialize the socket and send the meta query
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(query, (SERVER, PORT))

data, address = s.recvfrom(1024)
response = DNSRecord.parse(data)

# value should be buc:x where x is the number of chunks
val = response.rr[0].rdata.data[0].decode()

nr_buc = int(val.split(':')[1])
initial_checksum = val.split(':')[2]
print(nr_buc)

# f is open in wb because we will write in binary because of the encoding and decoding
f = open(f'downloads/{filename}', 'wb')

for i in range(nr_buc):
    query = DNSRecord(q=DNSQuestion(f'buc{i}.{filename}.tunnel.andrei12225.engineer', QTYPE.TXT)).pack()
    s.settimeout(3)
    print(i)

    # we try 3 times to receive the packets
    for j in range(3):
        try:
            s.sendto(query, (SERVER, PORT))
            data, adress = s.recvfrom(1024)
            if data is not None:
                break
        except socket.timeout:
            print("UDP packet was lost! Trying again...")

        # if it doesn't work the third time, wait for a bit (the connection might be down) and try one last time
        if j == 2:
            print('Trying one last time...')
            sleep(3)
            try:
                s.sendto(query, (SERVER, PORT))
                data, adress = s.recvfrom(1024)
            
                if data is not None:
                    break
            except socket.timeout:
                print(f"Bucata {i} could not be received!")
    
    else: # if no break was called, it means there was no data, break the original for and stop the client process
        break

    # get the first txt data of the first record and decode it
    val = DNSRecord.parse(data).rr[0].rdata.data[0].decode()

    # we have to decode it because the server encodes it (smart)
    val = base64.b64decode(val)

    f.write(val)

final_checksum = get_md5(f'downloads/{filename}')

if initial_checksum == final_checksum:
    print("The file was transfered successfully!")
else:
    print("The file was corrupted during transfer!")

f.close()    