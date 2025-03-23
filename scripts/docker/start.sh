#!/bin/bash

# Import utils
source ./scripts/utils.sh

# Default environment
FLASK_ENV='development'

# Parse and export command-line options as environment variables
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env)
      FLASK_ENV="$2"
      jada_echo "Environment set to: $FLASK_ENV"
      export FLASK_ENV="$FLASK_ENV"
      
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

docker-compose up jada-server --remove-orphans