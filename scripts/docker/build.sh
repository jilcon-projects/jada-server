#!/bin/bash

docker-compose pull

docker-compose run --entrypoint=./scripts/install.sh jada-server