FROM python:3.9.6

RUN apt-get update && apt-get install -y redis-server