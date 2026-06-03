import hashlib
import socket
import os
import base64
from time import sleep
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, TXT, QTYPE, RCODE


# we will use this to check against the md5 checksum we will get when we ask for metadata
def get_md5(filename):
    hash = hashlib.md5()
    with open(filename, 'rb') as f:
        # read the file in bucati of 8192 so we dont run out of memory in the case of massive files
        while buc := f.read(8192):
            hash.update(buc)
    return hash.hexdigest()


def start_download(filename):
    # ip of the server, obv
    SERVER = '172.10.0.30'
    PORT = 5002
    META_DOMAIN = f'meta.{filename}.tunnel.andrei12225.engineer'
    BUCSIZE = 180

    try:
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

        yield f'data: Total number of chunks: {nr_buc}\n\n'

        sleep(1)
    except Exception as e:
        yield f"event: error\ndata: Error occurred while fetching metadata: {e}\n\n"
        return

    # start is the first chunk the server will read and send to
    start = 0

    # theoretically, if the downloads directory wouldn't exist it would crash so i added this here
    os.makedirs('downloads', exist_ok=True)

    if os.path.exists(f'downloads/{filename}'):
        size = os.path.getsize(f'downloads/{filename}')
        already_written_bucati = size // BUCSIZE

        # if the last chunk was partially written, we have to clean it up and start fresh
        if size % BUCSIZE != 0:
            with open(f'downloads/{filename}', 'a+b') as temp:
                temp.truncate(already_written_bucati * BUCSIZE)

        if already_written_bucati > 0:
            yield f"data: File was already partially written! Continuing from chunk {already_written_bucati - 1}...\n\n"
            start = already_written_bucati


    # f is open in ab because we will write in binary because of the encoding and decoding
    f = open(f'downloads/{filename}', 'ab')


    for i in range(start, nr_buc):
        query = DNSRecord(q=DNSQuestion(f'buc{i}.{filename}.tunnel.andrei12225.engineer', QTYPE.TXT)).pack()
        s.settimeout(3)
        yield f"data: Getting bucata {i}...\n\n"

        # we try 3 times to receive the packets
        for j in range(3):
            try:
                s.sendto(query, (SERVER, PORT))
                data, adress = s.recvfrom(1024)
                if data is not None:
                    break
            except socket.timeout:
                yield "data: UDP packet was lost! Trying again...\n\n"

            # if it doesn't work the third time, wait for a bit (the connection might be down) and try one last time
            if j == 2:
                yield 'data: Trying one last time...\n\n'
                sleep(3)
                try:
                    s.sendto(query, (SERVER, PORT))
                    data, adress = s.recvfrom(1024)
                
                    if data is not None:
                        break
                except socket.timeout:
                    yield f"data: Bucata {i} could not be received!\n\n"
        
        else: # if no break was called, it means there was no data, break the original for and stop the client process
            break

        # get the first txt data of the first record and decode it
        val = DNSRecord.parse(data).rr[0].rdata.data[0].decode()

        # we have to decode it because the server encodes it (smart)
        val = base64.b64decode(val)

        f.write(val)

    f.close()    

    # close the file before the calculating the checksum, so that it gives the correct output
    final_checksum = get_md5(f'downloads/{filename}')

    yield f"data: Download finished! Calculating checksum...\n\n"

    sleep(1)

    yield f"data: Initial checksum: {initial_checksum}\n\n"
    sleep(1)
    yield f"data: Final checksum: {final_checksum}\n\n"
    sleep(1)

    if initial_checksum == final_checksum:
        yield f"data: The file was transfered successfully!\n\n"
        
        sleep(1)

        yield f"data: DONE\n\n"
    else:
        yield f"data: The file was corrupted during transfer!\n\n"
