FROM python:3-slim

WORKDIR /app

COPY . .

RUN pip install Flask

CMD ["flask", "--app", "server", "run", "--host=0.0.0.0"]