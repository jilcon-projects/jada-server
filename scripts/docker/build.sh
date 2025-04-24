#!/bin/bash

docker compose pull

docker compose build --entrypoint=./scripts/install.sh jada-server --remove-orphans