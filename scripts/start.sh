#!/bin/bash

# Import utils
source ./scripts/utils.sh

# Function to start Flask server
start_server() {
  jada_echo "${cyan}Starting Flask server...${clear}"

  source .venv/bin/activate
  
  python -m flask run --host=0.0.0.0 --port=$PORT
}

# Trap Ctrl+C (SIGINT) to call the shutdown function
trap "shutdown" SIGINT

# Start all services
start_server