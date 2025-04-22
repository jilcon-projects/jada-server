#!/bin/bash

docker-compose pull

docker-compose build jada-server
docker-compose run --entrypoint=./scripts/install.sh jada-server --remove-orphans