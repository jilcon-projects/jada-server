#!/bin/bash

# Import utils
source ./scripts/utils.sh

# Function to start Flask server
start_server() {
  jada_echo "${cyan}Starting application server...${clear}"

  source .venv/bin/activate
  
  python main.py &
  
  # Update services pids
  services_pids[0]=$!
  
  sleep 1
  
  is_server_started
  
  # If backend server fails to start after set time, kill server and exit process
  if [ $? -ne 0 ]; then
    jada_echo "${red}TIMEOUT: Server could not start within $timeout seconds.${clear}"
    shutdown
  fi

  # Server is fully started
  jada_echo "${green}Server is active and running!${clear}"
}

# Trap Ctrl+C (SIGINT) to call the shutdown function
trap "shutdown" SIGINT

# Start all services
start_server

# Wait for services
wait $services_pids