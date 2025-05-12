#!/bin/bash

# Import utils
source ./scripts/utils.sh

COMPOSE_BAKE=true docker compose up jada-server --remove-orphans