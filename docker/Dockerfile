FROM golang:1-alpine3.8 AS build
ADD  ./ ${GOPATH}/src/github.com/globocom/gsh
WORKDIR ${GOPATH}/src/github.com/globocom/gsh
RUN apk add --update git && \
    go get -u github.com/golang/dep/cmd/dep && \
    dep ensure --update && \
    go build -o /tmp/gsh-api ./api && \
    go build -o /tmp/gsh-agent ./agent

FROM alpine:3.8 AS gsh-api
COPY --from=build /tmp/gsh-api /usr/local/bin
ADD ./docker/scripts /tmp/scripts
RUN chmod +x /tmp/scripts/api-run.sh
CMD ["/tmp/scripts/api-run.sh"]

FROM alpine:3.8 AS gsh-target-machine
COPY --from=build /tmp/gsh-agent /usr/local/bin
ADD ./docker/scripts /tmp/scripts
RUN apk add --no-cache openssh && \
    chmod +x /tmp/scripts/target-machine-run.sh
CMD ["/tmp/scripts/target-machine-run.sh"]
