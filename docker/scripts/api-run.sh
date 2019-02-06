#!/bin/sh
#
# This script initializes gsh-api.
#

cd /tmp/scripts
echo "export GSH_CA_PUBLIC_KEY='`cat ca_host_key.pub`'" > .env
echo "export GSH_CA_PRIVATE_KEY='`cat ca_host_key`'" >> .env
source .env

gsh-api
