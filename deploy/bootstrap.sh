#!/bin/sh
# Lightsail Ubuntu 24.04 user data. No credentials or application payloads.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
# Prevent request memory being written to swap or core dumps.
swapoff -a
sed -i '/^[^#].*[[:space:]]swap[[:space:]]/s/^/# disabled for ephemeral request data: /' /etc/fstab
printf '* hard core 0\n* soft core 0\n' > /etc/security/limits.d/99-no-core.conf
sysctl -w fs.suid_dumpable=0
printf 'fs.suid_dumpable=0\nkernel.core_pattern=|/bin/false\n' > /etc/sysctl.d/99-no-core.conf
sysctl --system
