FROM golang:1-alpine3.8 AS build
ADD  ./ ${GOPATH}/src/github.com/globocom/gsh
WORKDIR ${GOPATH}/src/github.com/globocom/gsh
RUN apk add --update git && \
    go get -u github.com/golang/dep/cmd/dep && \
    dep ensure --update && \
    go build -o /tmp/gsh-api ./api

FROM alpine:3.8 AS gsh-api
COPY --from=build /tmp/gsh-api /usr/local/bin
CMD ["gsh-api"]