#!/bin/bash

source .env

# docker tag $APP_NAME $DOCKER_USERNAME/$APP_NAME:latest
docker tag jada astongemmy/jada:latest
docker push astongemmy/jada:latest