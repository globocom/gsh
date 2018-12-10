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

## References

This project is based on a number of other similar projects.

- https://github.com/mikesmitty/curse
- https://github.com/Netflix/bless
