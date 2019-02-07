# gsh

GSH is an OpenID Connect-compatible authentication system for systems using OpenSSH servers consisting of an out-of-box binary set.
Its use requires only a few configurations in the `sshd_config` file, allowing for a staged migration of an infrastructure based on PAM authentication (LDAP/AD/Kerberos/etc) to an authentication structure with OpenID Connect and SSH certificates.

<p allign="center">
  <img src="https://github.com/globocom/gsh/wiki/images/gsh_docker.gif" />
</p>       

## Want to know more?

Take a look at our excellent [documentation](https://github.com/globocom/gsh/wiki)!

## References

This project is based on a number of other similar projects.

- https://github.com/mikesmitty/curse
- https://github.com/Netflix/bless
- https://github.com/uber/pam-ussh
- https://code.fb.com/security/scalable-and-secure-access-with-ssh/
