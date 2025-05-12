#!/bin/bash

COMPOSE_BAKE=true docker compose pull

COMPOSE_BAKE=true docker compose run --entrypoint=./scripts/install.sh jada-server --remove-orphans