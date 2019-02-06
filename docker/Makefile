.SILENT:
.DEFAULT_GOAL := help

COLOR_RESET = \033[0m
COLOR_COMMAND = \033[36m
COLOR_YELLOW = \033[33m
COLOR_GREEN = \033[32m
COLOR_RED = \033[31m

PROJECT := GSH

## Installs a development environment
install: environment deploy msg

## Composes project using docker-compose
deploy:
	docker-compose down
	docker-compose up --build -d
	rm ./scripts/ca_host_key ./scripts/ca_host_key.pub

## Initializes environment variables
environment:
	chmod +x scripts/env.sh
	./scripts/env.sh

## Prints message after deploy stage
msg:
	chmod +x scripts/check-init.sh
	./scripts/check-init.sh


## Prints help message
help:
	printf "\n${COLOR_YELLOW}${PROJECT}\n------\n${COLOR_RESET}"
	awk '/^[a-zA-Z\-\_0-9\.%]+:/ { \
		helpMessage = match(lastLine, /^## (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")); \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			printf "${COLOR_COMMAND}$$ make %s${COLOR_RESET} %s\n", helpCommand, helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST) | sort
	printf "\n"
	