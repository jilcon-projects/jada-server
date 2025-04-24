#!/bin/bash

pip install docker-compose;

pip install docker==6.1.3;

docker-compose pull

docker-compose build --entrypoint=./scripts/install.sh jada-server --remove-orphans