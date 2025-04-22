# FROM python:3.9.6

# RUN apt-get update && apt-get install -y redis-server

FROM --platform=linux/amd64 python:3.9.6

ENV PIP_DISABLE_PIP_VERSION_CHECK 1
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Define build arguments for environment variables
ARG CORS_ORIGIN
ARG FLASK_ENV
ARG FLASK_APP
ARG APP_NAME
ARG APP_URL
ARG PORT

# Set environment variables
ENV CORS_ORIGIN=${CORS_ORIGIN}
ENV FLASK_ENV=${FLASK_ENV}
ENV FLASK_APP=${FLASK_APP}
ENV APP_NAME=${APP_NAME}
ENV APP_URL=${APP_URL}
ENV PORT=${PORT}

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt
COPY ./scripts /app/scripts

RUN apt-get update && apt-get install -y redis-server

RUN ./scripts/install.sh

COPY . /app

# EXPOSE 8080

# RUN ./scripts/start.sh

CMD ["python", "/app/main.py"]
