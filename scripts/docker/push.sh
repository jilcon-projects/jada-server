#!/bin/bash

source .env

docker tag $APP_NAME $DOCKER_USERNAME/$APP_NAME:latest
docker push $DOCKER_USERNAME/$APP_NAME:latest