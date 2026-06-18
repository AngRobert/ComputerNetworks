FROM python:3.12-slim

WORKDIR /DohEndpoint

COPY . .

RUN pip3 install scapy

RUN pip3 install pip "fastapi[standard]"

CMD ["python3" , "-u" , "doh_decoder.py"] 

