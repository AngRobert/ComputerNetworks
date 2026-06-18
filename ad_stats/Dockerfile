FROM python:3.12-slim

WORKDIR /app

COPY . .

RUN pip install flask flask-cors

EXPOSE 5050

CMD ["python3", "-u", "app.py"]
