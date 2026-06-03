FROM python:3-slim

WORKDIR /app

COPY . .

RUN pip install scapy dnslib

CMD ["python", "server.py"]