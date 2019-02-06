#!/bin/bash
#
# This script verifies if GSH containers have properly start-up.
#

COLOR_RED='\033[31m'
COLOR_YELLOW='\033[33m'
COLOR_GREEN='\033[32m'
COLOR_RESET='\033[0m'

EXPECTED=WORKING
APIPORT=8000
KEYCLOAKPORT=8080
DBPORT=3306
TARGETMACHINEPORT=22000
TRIES=30

printf "${COLOR_YELLOW}GSH is starting... \n${COLOR_RESET}"

while : ; do
	RESULT=`curl http://localhost:$APIPORT/status/live -s`
	if [ "$RESULT" == "$EXPECTED" ]; then
		break
	fi
    if [ $TRIES == 0 ]; then
        break
    fi
    TRIES=$TRIES-1
	sleep 5
	printf "${COLOR_YELLOW}GSH is still starting... \n${COLOR_RESET}"
done

if [ $TRIES == 0 ]; then
    printf "${COLOR_RED} Oops. Something went wrong! Please check gsh_api logs for details${COLOR_RESET}\n"
else
    printf "${COLOR_GREEN}GSH is now running!${COLOR_RESET}\n"
    printf "${COLOR_GREEN}GSH api can be found at: ${COLOR_YELLOW}http://localhost:$APIPORT${COLOR_RESET}\n"
    printf "${COLOR_GREEN}GSH keycloak can be found at: ${COLOR_YELLOW}http://localhost:$KEYCLOAKPORT${COLOR_RESET}\n"
    printf "${COLOR_GREEN}GSH database can be found at: ${COLOR_YELLOW}http://localhost:$DBPORT${COLOR_RESET}\n"
    printf "${COLOR_GREEN}GSH target machine can be found at: ${COLOR_YELLOW}http://localhost:$TARGETMACHINEPORT${COLOR_RESET}\n"
fi