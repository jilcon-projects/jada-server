#!/bin/bash

source .env
cat .env
echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< APP NAME IS >>>>>>>>>>>>>>>>>>>>>>>>>>> ${APP_NAME}"
docker tag $APP_NAME $DOCKER_USERNAME/$APP_NAME:latest
docker push $DOCKER_USERNAME/$APP_NAME:latest