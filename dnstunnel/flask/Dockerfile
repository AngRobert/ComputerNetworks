FROM python:3-slim

WORKDIR /app

COPY . .

RUN pip install flask dnslib

CMD ["python", "flask_server.py"]