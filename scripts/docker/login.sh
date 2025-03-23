#!/bin/bash

source .env

echo $DOCKER_PASSWORD | docker login -u $DOCKER_USERNAME --password-stdin