#!/bin/bash

source .env

docker tag $DOCKER_USERNAME/$APP_NAME:latest
docker push $DOCKER_USERNAME/$APP_NAME:latest