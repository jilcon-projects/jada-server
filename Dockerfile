FROM python:3.9.6

ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y redis-server