# FROM python:3.9.6

# RUN apt-get update && apt-get install -y redis-server

FROM python:3.10.17

# Define build arguments for environment variables
ARG PYTHONDONTWRITEBYTECODE
ARG CORS_ORIGIN
ARG FLASK_ENV
ARG FLASK_APP
ARG APP_NAME
ARG APP_URL

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=$PYTHONDONTWRITEBYTECODE
ENV CORS_ORIGIN=$CORS_ORIGIN
ENV FLASK_ENV=$FLASK_ENV
ENV FLASK_APP=$FLASK_APP
ENV APP_NAME=$APP_NAME
ENV APP_URL=$APP_URL

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt
COPY ./scripts /app/scripts

RUN apt-get update && apt-get install -y redis-server

RUN /app/scripts/install.sh

COPY . /app

CMD ["gunicorn", "--bind", ":8080", "--workers", "1", "--threads", "8", "--timeout", "0", "main:app"]