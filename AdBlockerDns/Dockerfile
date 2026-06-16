FROM python:3.12-slim

WORKDIR /DNS

COPY . .

RUN pip3 install scapy

CMD ["python3" , "-u" , "udp_dns_server.py"] 
#-u e ca sa printeze in voulum
