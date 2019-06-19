.SILENT:
.DEFAULT_GOAL := help

GO ?= go
GOROOT ?= $(shell $(GO) env GOROOT)
GOPATH ?= $(shell $(GO) env GOPATH)
GOBIN ?= $(GOPATH)/bin
GODEP ?= $(GOBIN)/dep
GOLINT ?= $(GOBIN)/golint
GOSEC ?= $(GOBIN)/gosec

GSHBIN ?= gsh

COLOR_RESET = \033[0m
COLOR_COMMAND = \033[36m
COLOR_YELLOW = \033[33m
COLOR_GREEN = \033[32m
COLOR_RED = \033[31m

PROJECT := GSH

## Gets all go test dependencies
get-test-deps:
	$(GO) get -u github.com/golang/dep/cmd/dep
	$(GO) get -u golang.org/x/lint/golint
	$(GO) get -u github.com/securego/gosec/cmd/gosec

## Runs a security static analysis using Gosec
check-sec:
	$(GOSEC) ./... 2> /dev/null

## Runs lint
lint:
	$(GOLINT) $(shell $(GO) list ./...)

## Perfoms all make tests
test: get-test-deps lint check-sec

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

## build all binaries at dist folder
release:
	rm -rf dist
	mkdir dist
	for GOOS in darwin linux windows; \
	do \
		for GOARCH in amd64; \
		do \
			echo "-> Compiling for $${GOOS}/$${GOARCH}..."; \
			mkdir -p dist/$${GOOS}/$${GOARCH}; \
			GOOS=$${GOOS} GOARCH=$${GOARCH} $(GO) build -o dist/$${GOOS}/$${GOARCH}/gsh cli/main.go; \
			if [ $${GOOS} == "darwin" ]; \
			then \
				echo "-> Signing gsh CLI for $${GOOS}/$${GOARCH} with $${DEVELOPER_CERT_ID} cert..."; \
				codesign -s $${DEVELOPER_CERT_ID} dist/$${GOOS}/$${GOARCH}/gsh; \
			fi; \
			GOOS=$${GOOS} GOARCH=$${GOARCH} $(GO) build -o dist/$${GOOS}/$${GOARCH}/gsh-api api/main.go; \
			GOOS=$${GOOS} GOARCH=$${GOARCH} $(GO) build -o dist/$${GOOS}/$${GOARCH}/gsh-agent agent/main.go; \
			tar cfz dist/gsh-$${GOOS}-$${GOARCH}.tar.gz README.md LICENSE -C dist/$${GOOS}/$${GOARCH} .; \
		done; \
	done

tar:
## build tar for binaries at dist folder
	rm -rf dist/*.tar.gz
	for GOOS in darwin linux windows; \
	do \
		for GOARCH in amd64; \
		do \
			echo "-> Generate tar for $${GOOS}/$${GOARCH}..."; \
			tar cfz dist/gsh-$${GOOS}-$${GOARCH}.tar.gz README.md LICENSE -C dist/$${GOOS}/$${GOARCH} .; \
		done; \
	done