#!/usr/bin/env bash
# =============================================================================
# DiscoLauncher Backend — Update Script
# Run this on the Proxmox HOST to update an existing installation
# Usage: bash update.sh [CONTAINER_ID]
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }

CT_ID=${1:-""}
if [ -z "$CT_ID" ]; then
  read -rp "Container ID: " CT_ID
fi

info "Updating DiscoLauncher Backend in container ${CT_ID}..."

pct exec ${CT_ID} -- bash -c '
  cd /opt/discolauncher-backend
  git pull --ff-only
  npm install --omit=dev
  systemctl restart discolauncher
  systemctl status discolauncher --no-pager -l
'

success 'DiscoLauncher Backend updated and restarted!'
