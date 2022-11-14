FROM alpine:3.8 AS gsh-api
ADD ./dist/linux/amd64/ /usr/local/bin
ADD ./docker/scripts /tmp/scripts
RUN chmod +x /tmp/scripts/api-run.sh
CMD ["/tmp/scripts/api-run.sh"]

FROM alpine:3.8 AS gsh-target-machine
ADD ./dist/linux/amd64/ /usr/local/bin
ADD ./docker/scripts /tmp/scripts
RUN apk add --no-cache openssh && \
    chmod +x /tmp/scripts/target-machine-run.sh
CMD ["/tmp/scripts/target-machine-run.sh"]
