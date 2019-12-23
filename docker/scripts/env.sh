#!/bin/sh
#
# This script creates .env file, which later is used by the containers.
#

rm ./scripts/ca_host_key ./scripts/ca_host_key.pub
yes y | ssh-keygen -t rsa -f ./scripts/ca_host_key -q -N ''

MYSQL_ROOT_PASSWORD="rootPass$RANDOM$RANDOM"
MYSQL_DATABASE="gsh"
MYSQL_USER="user$RANDOM$RANDOM"
MYSQL_PASSWORD="userPass$RANDOM$RANDOM"

KEYCLOAK_USER="admin$RANDOM$RANDOM"
KEYCLOAK_PASSWORD="adminPass$RANDOM$RANDOM"

PORT=8000
GSH_CHANNEL_SIZE=100

GSH_WORKERS_AUDIT=1
GSH_WORKERS_LOG=1

GSH_STORAGE_DRIVER=mysql
GSH_STORAGE_MAX_ATTEMPTS=5
GSH_STORAGE_MAX_CONNECTIONS=20
GSH_STORAGE_DEBUG=1
GSH_STORAGE_URI="$MYSQL_USER:$MYSQL_PASSWORD@tcp(gsh_db:3306)/gsh?charset=utf8&parseTime=True&multiStatements=true"
GSH_CASBIN_URI="$MYSQL_USER:$MYSQL_PASSWORD@tcp(gsh_db:3306)/casbin?charset=utf8&parseTime=True&multiStatements=true"
GSH_PERM_ADMIN=admin@example.com

GSH_CA_EXTERNAL=0
GSH_CA_ENDPOINT="https://example.com"
GSH_CA_PUBLIC_KEY_URL="/public_key"
GSH_CA_SIGNER_URL="/sign"
GSH_CA_LOGIN_URL="/login"
GSH_CA_ROLE_ID="vault role id"
GSH_CA_SIGNED_CERT_DURATION=600000000000

GSH_OIDC_BASE_URL=http://gsh_keycloak:8080/auth/realms
GSH_OIDC_REALM=gsh
GSH_OIDC_AUDIENCE=gsh
GSH_OIDC_AUTHORIZED_PARTY=gsh
GSH_OIDC_CLAIM=PreferredUsername
GSH_OIDC_CLAIM_NAME=preferred_username
GSH_OIDC_ISSUER=http://gsh_keycloak:8080/
GSH_OIDC_CERTS=http://gsh_keycloak:8080/.well-known/jwks.json
GSH_OIDC_CALLBACK_PORT=30000

echo "Keycloak admin username: $KEYCLOAK_USER"
echo "Keycloak admin password: $KEYCLOAK_PASSWORD"

# Export environment variables to .env file that will be used in build stage

echo "MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASSWORD" > .env
echo "MYSQL_DATABASE=$MYSQL_DATABASE" >> .env
echo "MYSQL_USER=$MYSQL_USER" >> .env
echo "MYSQL_PASSWORD=$MYSQL_PASSWORD" >> .env

echo "KEYCLOAK_USER=$KEYCLOAK_USER" >> .env
echo "KEYCLOAK_PASSWORD=$KEYCLOAK_PASSWORD" >> .env
echo "KEYCLOAK_IMPORT=/tmp/scripts/gsh-realm.json" >> .env

echo "PORT=$PORT" >> .env
echo "GSH_CHANNEL_SIZE=$GSH_CHANNEL_SIZE" >> .env

echo "GSH_WORKERS_AUDIT=$GSH_WORKERS_AUDIT" >> .env
echo "GSH_WORKERS_LOG=$GSH_WORKERS_LOG" >> .env

echo "GSH_STORAGE_DRIVER=$GSH_STORAGE_DRIVER" >> .env
echo "GSH_STORAGE_MAX_ATTEMPTS=$GSH_STORAGE_MAX_ATTEMPTS" >> .env
echo "GSH_STORAGE_MAX_CONNECTIONS=$GSH_STORAGE_MAX_CONNECTIONS" >> .env
echo "GSH_STORAGE_DEBUG=$GSH_STORAGE_DEBUG" >> .env
echo "GSH_STORAGE_URI=$GSH_STORAGE_URI" >> .env
echo "GSH_CASBIN_URI=$GSH_CASBIN_URI" >> .env
echo "GSH_PERM_ADMIN=$GSH_PERM_ADMIN" >> .env

echo "GSH_CA_EXTERNAL=$GSH_CA_EXTERNAL" >> .env
echo "GSH_CA_ENDPOINT=\"$GSH_CA_ENDPOINT\"" >> .env
echo "GSH_CA_PUBLIC_KEY_URL=\"$GSH_CA_PUBLIC_KEY_URL\"" >> .env
echo "GSH_CA_SIGNER_URL=\"$GSH_CA_SIGNER_URL\"" >> .env
echo "GSH_CA_LOGIN_URL=\"$GSH_CA_LOGIN_URL\"" >> .env
echo "GSH_CA_ROLE_ID=\"$GSH_CA_ROLE_ID\"" >> .env
echo "GSH_CA_SIGNED_CERT_DURATION=$GSH_CA_SIGNED_CERT_DURATION" >> .env

echo "GSH_OIDC_BASE_URL=$GSH_OIDC_BASE_URL" >> .env
echo "GSH_OIDC_REALM=$GSH_OIDC_REALM" >> .env
echo "GSH_OIDC_AUDIENCE=$GSH_OIDC_AUDIENCE" >> .env
echo "GSH_OIDC_AUTHORIZED_PARTY=$GSH_OIDC_AUTHORIZED_PARTY" >> .env
echo "GSH_OIDC_CLAIM=$GSH_OIDC_CLAIM" >> .env
echo "GSH_OIDC_CLAIM_NAME=$GSH_OIDC_CLAIM_NAME" >> .env
echo "GSH_OIDC_ISSUER=$GSH_OIDC_ISSUER" >> .env
echo "GSH_OIDC_CERTS=$GSH_OIDC_CERTS" >> .env
echo "GSH_OIDC_CALLBACK_PORT=$GSH_OIDC_CALLBACK_PORT" >> .env
