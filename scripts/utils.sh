#!/bin/bash

# Config for pinging all server apps.
FLASK_URL='http://localhost:6000'
start_time=$(date +%s)
timeout=30

# Define global variables
purple='\033[35m'
yellow='\033[33m'
green='\033[92m'
clear='\033[0m'
cyan='\033[36m'
blue='\033[34m'
red='\033[31m'

# Apps list
apps=(
  'api'
)

# Check if all server apps have started successfully.
function check_server_status() {
  jada_echo "${green}Pinging all apps for activity status...${clear}"

  if ping_server_apps; then
    jada_echo "${green}All apps are up and running!${clear}"
  else
    jada_echo "${red}TIMEOUT: All apps could not start within $timeout seconds.${clear}"
    exit 0
  fi
}

# Ping all server apps within a specified time.
function ping_server_apps() {
  for app in "${apps[@]}"; do

    while ! ping_app "$app"; do
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

# Customize all echo messages.
function jada_echo() {
  echo -e "${yellow}JADA${clear} --> $@"
}

# Shutdown server.
function shutdown() {
  docker compose down
}

# Ping app.
function ping_app() {
  local app="${purple}$(echo "$1" | tr '[:lower:]' '[:upper:]')${clear}"
  local ping_url="$FLASK_URL/${1}/ping"

  jada_echo "${cyan}Pinging ${app} ${cyan}app via ${ping_url}${clear}"

  status_code=$(curl -s -o /dev/null -w "%{http_code}" $ping_url)
  
  if [ $status_code -eq 200 ]; then
    jada_echo "${green}${app} app started successfully!"
    return 0
  else
    jada_echo "${red}Failed to start ${app} ${red}app!${clear}"
    return 1
  fi
}