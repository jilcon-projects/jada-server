#!/bin/bash

docker compose pull

# docker compose build jada-server
./scripts/install.sh

# docker-compose build --entrypoint=./scripts/install.sh jada-server --remove-orphans
docker compose build jada-server