#!/bin/bash

source .env

docker tag "$REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY/$SERVICE:$SHA"
# docker tag $APP_NAME $DOCKER_USERNAME/$APP_NAME:latest
docker tag jada astongemmy/jada:latest
docker push astongemmy/jada:latest