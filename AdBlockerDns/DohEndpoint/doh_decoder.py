import socket
# Am inlocuit importul scapy cu socket deoarece scapy nu este utilizat
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
    # Setam un timeout pentru a preveni blocarea buclei de evenimente in caz de timeout DNS
    simple_udp.settimeout(5.0)
    simple_udp.sendto(decoding(dns), ("dns_adblocker_udp", 53)) # Trimitem la serviciul de DNS din containerul separat

    try:
        dns_resp, adresa = simple_udp.recvfrom(65535) #luam toti bytes, ca in curs, probabil puteam pune si mai putin
    except socket.timeout:
        return Response(status_code=504, content="DNS server timeout")

    return Response(content = dns_resp, media_type="application/dns-message") #Response e functie fastapi, tipul de raspuns e dns...


@app.post("/dns_adblocker")
async def dns_post(dns: Request):

    cerere = await dns.body();

    simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    # Setam un timeout pentru a preveni blocarea buclei de evenimente in caz de timeout DNS
    simple_udp.settimeout(5.0)
    simple_udp.sendto(cerere, ("dns_adblocker_udp", 53)) # Trimitem la serviciul de DNS din containerul separat

    try:
        dns_resp, adresa = simple_udp.recvfrom(65535) #luam toti bytes, ca in curs, probabil puteam pune si mai putin
    except socket.timeout:
        return Response(status_code=504, content="DNS server timeout")

    return Response(content = dns_resp, media_type="application/dns-message") #Response e functie fastapi, tipul de raspuns e dns...


if __name__ == "__main__":
    import uvicorn
    # Pornim serverul ASGI (uvicorn) pe portul 5001 pentru a tine containerul activ
    uvicorn.run(app, host="0.0.0.0", port=5001)
