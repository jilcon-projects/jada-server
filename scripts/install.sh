#!/bin/bash

source ./scripts/utils.sh

trap 'jada_echo "${red}Dependencies installation cancelled!${clear}"; exit' SIGINT

jada_echo "${cyan}Installing dependencies...${clear}"

python -m venv .venv && source .venv/bin/activate &&

pip install -r requirements.txt --upgrade pip

jada_echo "${green}Dependencies installed successfully!${clear}"