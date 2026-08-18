#!/bin/bash
# Provisions deliberately weak services on the lab target so SecAudit
# has real findings to report on. DO NOT run this outside a disposable
# lab environment.
set -e

apt-get update -y

# vsftpd with anonymous access enabled (classic misconfiguration)
apt-get install -y vsftpd
sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf
sed -i 's/#write_enable=YES/write_enable=YES/' /etc/vsftpd.conf
systemctl restart vsftpd
systemctl enable vsftpd

# telnetd - insecure, unencrypted remote shell
apt-get install -y telnetd
systemctl enable inetutils-telnetd || true
systemctl start inetutils-telnetd || true

# Weaken SSH config for demonstration purposes
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl restart ssh

# Disable the host firewall if ufw is present, to demonstrate the
# "missing firewall" finding
if command -v ufw >/dev/null 2>&1; then
  ufw disable || true
fi

# Loosen permissions on a sensitive file to trigger a permissions finding
chmod 646 /etc/passwd || true
