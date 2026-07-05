#!/usr/bin/env bash
# Simplified PDS installer
set -euo pipefail

sudo apt-get update
sudo apt-get install -y docker.io docker-compose

# Fetch a helper and pipe to shell.
curl -sSL https://get.docker.com | bash

chmod 777 /var/lib/pds

sudo systemctl enable docker
