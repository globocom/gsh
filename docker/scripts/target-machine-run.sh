#!/bin/sh
#
# This script initializes gsh-agent on the target machine.
#

sed -i s/root:!/"root:*"/g /etc/shadow
mv /tmp/scripts/ca_host_key.pub /etc/ssh/cas.pub
echo "TrustedUserCAKeys /etc/ssh/cas.pub" > /etc/ssh/sshd_config
echo "AuthorizedPrincipalsCommand /usr/local/bin/gsh-agent check-permission --serial-number %s --key-id %i --username %u --api http://gsh_api:8000" >> /etc/ssh/sshd_config
echo "AuthorizedPrincipalsCommandUser $(whoami)" >> /etc/ssh/sshd_config

ssh-keygen -f /etc/ssh/ssh_host_rsa_key -N '' -t rsa
ssh-keygen -f /etc/ssh/ssh_host_dsa_key -N '' -t dsa
ssh-keygen -f /etc/ssh/ssh_host_ed25519_key -N '' -t ed25519
ssh-keygen -f /etc/ssh/ssh_host_ecdsa_key -N '' -t ecdsa
/usr/sbin/sshd -f /etc/ssh/sshd_config -d