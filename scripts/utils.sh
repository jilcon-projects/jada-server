#!/bin/bash

# Timeout for pinging all services
start_time=$(date +%s)
timeout=60

# Define global variables
purple='\033[35m'
yellow='\033[33m'
green='\033[92m'
clear='\033[0m'
cyan='\033[36m'
blue='\033[34m'
red='\033[31m'

# Services pids
services_pids=()

# Apps list
services=(
  'api'
)

# Check if all services have started within a specified time
function is_server_started() {
  for service in "${services[@]}"; do
    while ! ping_service "$service"; do
      current_time=$(date +%s)
      elapsed_time=$((current_time - start_time))
      
      if [ $elapsed_time -ge $timeout ]; then
        return 1
      fi

      sleep 1
    done
  done

  return 0
}

# Ping started backend server
function ping_service() {
  local service="${purple}$(echo "$1" | tr '[:lower:]' '[:upper:]')${clear}"
  local ping_url="http://localhost:9000/${1}/ping"

  jada_echo "${cyan}Pinging ${service} ${cyan}service via ${ping_url}${clear}"

  status_code=$(curl -s -o /dev/null -w "%{http_code}" $ping_url)
  
  if [ $status_code -eq 200 ]; then
    jada_echo "${green}${service} service started successfully!"
    return 0
  else
    jada_echo "${red}Failed to start ${service} ${red}service!${clear}"
    return 1
  fi
}

# Customize all echo messages
jada_echo() {
  echo -e "${yellow}JADA${clear} --> $@"
}

# Shutdown/cleanup services
shutdown() {
  jada_echo "${cyan}Shutting down gracefully!${clear}"

  for index in ${!services_pids[@]}; do
    local service="${purple}$(echo "${services[$index]}" | tr '[:lower:]' '[:upper:]')${clear}"
    local pid=${services_pids[$index]}

    jada_echo "${cyan}Terminating ${service} ${cyan}service with PID: ${pid}...${clear}"
    
    if [ -n $pid ] && kill -0 $pid 2>/dev/null; then
      kill -15 ${pid}
      wait ${pid} 2>/dev/null || true
    fi
  done

  jada_echo "${green}Shutdown completed!${clear}"
  exit 0
}