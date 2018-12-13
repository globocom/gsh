# gsh

GSH is an OpenID Connect-compatible authentication system for systems using OpenSSH servers consisting of an out-of-box binary set.
Its use requires only a few configurations in the sshd_config file, allowing for a staged migration of an infrastructure based on PAM  authentication (LDAP/AD/Kerberos/etc) to an authentication structure used for OpenID Connect and SSH certificates.

## Architecture

- **GSH API** is responsible for authenticating and authorizing (via OpenID Connect) users who want to access some host using OpenSSH. The information provided via OpenID Connect is processed in the API to verify that the user can access the host and with which user the user can access.
After the validations, a certificate is issued and made available to the user for access to the requested host.

- **GSH Client** is responsible for communicating with the GSH API and performing the certificate requests. The client also has the stream that enables the client to authenticate locally using the terminal (via OpenID Connect).

- **GSH Command** is responsible for making auditing of the commands executed on the servers possible. When generating a certificate, the GSH API can include the force-command attribute where the OpenSSH server will run the GSH Command. This binary will send all the commands to the GSH API making it possible to audit everything that was done using the certificate issued for that connection.
The command is also responsible for enabling remote management of sessions, for example by enabling unauthorized session interruption.

- **GSH Agent** is responsible for periodically rotating the CA keys on the servers and signing the host keys in order to avoid TOFU problems. It runs in crontab and is installed by the GSH API.

- **GSH Principals** is responsible for confirming the mapping performed on the server-side certificate. It runs every time a certificate authentication is performed on the OpenSSH server and queries the GSH API to confirm the operation.

## User flow (terminal)

1. User runs `gsh 10.10.10.10` client
1.1 The client checks to see if an OpenID Connect JWT already exists in the `~/.gsh` directory of the user. If it exists and it is valid, it goes to step 1.5, if it does not exist or is not valid, it continues in 1.2
1.2 The client starts a local web server and redirects the user to the OpenID provider by pointing the local web server as the return URL
1.3 The user authenticates and the browser redirects the `code` to the client on the local web server
1.4 The client, with `code`, requests the user's access token (JWT).
1.5 The client, with the user's JWT, generates an SSH key pair and sends [a request to the API](https://github.com/globocom/gsh/wiki/routes-post-certificates)
1.6 The API processes the request, verifying that the user has the appropriate permissions and generates a certificate for the user
1.7 The client, with the SSH certificate and the keys already generated, makes a connection [using SSH on the server](https://github.com/globocom/gsh/wiki/manual-openssh-client)

## User flow (web)

1. User authenticates in web interface at gsh.example.com
1.1 The gsh.example.com application verifies that the user has a valid session if he does not redirect the user to the OpenID Connect authentication.
1.2 The user selects the server he would like to have access to and the configuration parameters (access time, remote user, key to be used)
1.3 The web interface generates a certificate for the user
1.4 The user uses the certificate to [connect to the server](https://github.com/globocom/gsh/wiki/manual-openssh-client)

## Server flow

1. The server receives the connection with the user's certificate
1.1 The SSH server checks if the certificate is signed by [one of the configured CAs] (https://man.openbsd.org/sshd_config#TrustedUserCAKeys)
1.2 The SSH server checks if the `principal` attribute in the certificate is valid using [gsh-command] (https://man.openbsd.org/sshd_config#AuthorizedPrincipalsCommand)
1.3 `gsh-command` receives the parameters of the certificate and verifies in the GSH API if that connection should be authorized. If it is not, it blocks the connection, if it does, it returns the [server-expected configuration] (http://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT)
1.4 The SSH server checks whether the certificate has the `force-command` attribute. If it does, it executes `gsh-shell` which makes it possible to audit the commands performed on the accessed host.

## References

This project is based on a number of other similar projects.

- https://github.com/mikesmitty/curse
- https://github.com/Netflix/bless
