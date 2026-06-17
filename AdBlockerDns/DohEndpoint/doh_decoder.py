from scapy.all import *
from fastapi import *
import base64

app = FastAPI()

def decoding(cerere):

    padd_len = (4 - len(cerere) % 4) % 4
    padding = "=" * padd_len
    final_str = cerere + padding
    
    send =  base64.urlsafe_b64decode(final_str)
    return send



@app.get("/dns_adblocker") #nu folosim root pt ca e folosita de website-ul default
async def dns_get(dns: str): #in url o sa fie dns=
    #cererea e un url care are, dupa = un pchet dns codat in base64URL
    #ca sa o decodam, trebuie sa fie multiplu de 4, punem padding cu == la sfarsit

    simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    simple_udp.sendto(decoding(dns), ("127.0.0.1", 53)) #trimitem la serverul dns care asculta pe localhost 53

    dns_resp, adresa = simple_udp.recvfrom(65535) #luam toti bytes, ca in curs, probabil puteam pune si mai putin

    return Response(content = dns_resp, media_type="application/dns-message") #Response e functie fastapi, tipul de raspuns e dns...


@app.post("/dns_adblocker")
async def dns_post(dns: Request):

    cerere = await dns.body();

    simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    simple_udp.sendto(decoding(dns), ("127.0.0.1", 53)) #trimitem la serverul dns care asculta pe localhost 53

    dns_resp, adresa = simple_udp.recvfrom(65535) #luam toti bytes, ca in curs, probabil puteam pune si mai putin

    return Response(content = dns_resp, media_type="application/dns-message") #Response e functie fastapi, tipul de raspuns e dns...










