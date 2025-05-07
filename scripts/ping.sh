#!/bin/bash

# Import utils
source ./scripts/utils.sh

ping_server_apps() {
  jada_echo "${green}Pinging all apps for activity status...${clear}"

  are_all_apps_started
  
  if [ $? -ne 0 ]; then
    jada_echo "${red}TIMEOUT: All apps could not start within $timeout seconds.${clear}"
    exit 0
  fi

  jada_echo "${green}All apps are up and running!${clear}"
}

ping_server_apps