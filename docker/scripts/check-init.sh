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
TRIES=480
RESULT=1
LOADING=0

printf "${COLOR_YELLOW}GSH is starting... \n${COLOR_RESET}"

while : ; do
    if [ $RESULT != 0 ]; then
	    OUTPUT=`curl -s http://localhost:$APIPORT/status/live`
	    if [ "$OUTPUT" == "$EXPECTED" ]; then
		    RESULT=0
	    fi
    fi
    `curl -s -f http://localhost:$KEYCLOAKPORT > /dev/null`
    if [ $? == 0 ] && [ $RESULT == 0 ] ; then
        break
    fi
    if [ $TRIES == 0 ] ; then
        break
    fi
    TRIES=$TRIES-1
	sleep 0.25 

    # Loading animation
    if [ $LOADING == 14 ]; then
        LOADING=0
    fi
    if [ $LOADING == 0 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (GSH-------) ${COLOR_RESET}"
    elif [ $LOADING == 1 ]; then
	    printf "\r${COLOR_YELLOW}GSH is still starting... (-GSH------) ${COLOR_RESET}"
    elif [ $LOADING == 2 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (--GSH-----) ${COLOR_RESET}"
    elif [ $LOADING == 3 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (---GSH----) ${COLOR_RESET}"
    elif [ $LOADING == 4 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (----GSH---) ${COLOR_RESET}"
    elif [ $LOADING == 5 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (-----GSH--) ${COLOR_RESET}"
    elif [ $LOADING == 6 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (------GSH-) ${COLOR_RESET}"
    elif [ $LOADING == 7 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (-------GSH) ${COLOR_RESET}"
    elif [ $LOADING == 8 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (------GSH-) ${COLOR_RESET}"
    elif [ $LOADING == 9 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (-----GSH--) ${COLOR_RESET}"
    elif [ $LOADING == 10 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (----GSH---) ${COLOR_RESET}"
    elif [ $LOADING == 11 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (---GSH----) ${COLOR_RESET}"
    elif [ $LOADING == 12 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (--GSH-----) ${COLOR_RESET}"
    elif [ $LOADING == 13 ]; then
        printf "\r${COLOR_YELLOW}GSH is still starting... (-GSH------) ${COLOR_RESET}"
    fi
    LOADING=$((LOADING+1))
    # End of loading animation

done

if [ $TRIES == 0 ]; then
    printf "${COLOR_RED} Oops. Something went wrong! Please check gsh_api logs for details${COLOR_RESET}\n"
else
    printf "\n\n${COLOR_GREEN}GSH is now running!${COLOR_RESET}\n"
    printf "${COLOR_GREEN}GSH api can be found at: ${COLOR_YELLOW}http://localhost:$APIPORT${COLOR_RESET}\n"
    printf "${COLOR_GREEN}GSH keycloak can be found at: ${COLOR_YELLOW}http://localhost:$KEYCLOAKPORT${COLOR_RESET}\n"
    printf "${COLOR_GREEN}GSH database can be found at: ${COLOR_YELLOW}http://localhost:$DBPORT${COLOR_RESET}\n"
    printf "${COLOR_GREEN}GSH target machine can be found at: ${COLOR_YELLOW}http://localhost:$TARGETMACHINEPORT${COLOR_RESET}\n"
fi