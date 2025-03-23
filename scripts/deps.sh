#!/bin/bash

source ./scripts/utils.sh

set -e

until redis-cli -h redis ping | grep -q "PONG" ; do
  >&2 jada_echo "Redis server not ready - retrying..."
  sleep 5
done

>&2 jada_echo "Redis is ready"

exec "$@"
