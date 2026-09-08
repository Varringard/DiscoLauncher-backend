#!/usr/bin/env bash
# =============================================================================
# DiscoLauncher Backend — Proxmox LXC Installer
# https://github.com/varrimain/DiscoLauncher-backend
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo -e "${CYAN}"
echo ' ____  _           _                            _              '
echo '|  _ \(_)___  ___ | |    __ _ _   _ _ __   ___| |__   ___ _ __'
echo '| | | | / __|/ __|| |   / _` | | | | '\''_ \ / __| '\''_ \ / _ \ '\''__|'
echo '| |_| | \__ \ (__ | |__| (_| | |_| | | | | (__| | | |  __/ |  '
echo '|____/|_|___/\___||_____\__,_|\__,_|_| |_|\___|_| |_|\___|_|  '
echo -e "${NC}"
echo -e "${GREEN}DiscoLauncher Backend — Proxmox LXC Installer${NC}"
echo ''

# Check Proxmox
if ! command -v pct &>/dev/null; then
  error 'This script must be run on a Proxmox VE host!'
fi

# Get next available container ID
NEXT_ID=$(pvesh get /cluster/nextid 2>/dev/null || echo 200)

# Interactive configuration
read -rp "Container ID [${NEXT_ID}]: " CT_ID; CT_ID=${CT_ID:-$NEXT_ID}
read -rp "Container name [discolauncher]: " CT_NAME; CT_NAME=${CT_NAME:-discolauncher}
read -rp "RAM (MB) [512]: " CT_RAM; CT_RAM=${CT_RAM:-512}
read -rp "Disk size (GB) [4]: " CT_DISK; CT_DISK=${CT_DISK:-4}
read -rp "Bridge [vmbr0]: " CT_BRIDGE; CT_BRIDGE=${CT_BRIDGE:-vmbr0}
read -rp "Admin password [admin123]: " CT_ADMIN_PASS; CT_ADMIN_PASS=${CT_ADMIN_PASS:-admin123}
read -rp "JWT secret [auto-generate]: " CT_JWT; CT_JWT=${CT_JWT:-$(openssl rand -hex 32)}

STORAGE=$(pvesm status -content rootdir | awk 'NR>1 {print $1; exit}')
info "Using storage: ${STORAGE}"

# Download Debian 12 template
TEMPLATE_STORAGE=$(pvesm status -content vztmpl | awk 'NR>1 {print $1; exit}')
DEBIAN_TEMPLATE=$(pveam list ${TEMPLATE_STORAGE} 2>/dev/null | grep debian-12 | awk '{print $1}' | head -1)

if [ -z "$DEBIAN_TEMPLATE" ]; then
  info 'Downloading Debian 12 LXC template...'
  pveam update
  DEBIAN_TEMPLATE_NAME=$(pveam available --section system | grep debian-12 | awk '{print $2}' | head -1)
  pveam download ${TEMPLATE_STORAGE} ${DEBIAN_TEMPLATE_NAME}
  DEBIAN_TEMPLATE="${TEMPLATE_STORAGE}:vztmpl/${DEBIAN_TEMPLATE_NAME}"
fi

info "Creating LXC container ${CT_ID} (${CT_NAME})..."
pct create ${CT_ID} ${DEBIAN_TEMPLATE} \
  --hostname ${CT_NAME} \
  --memory ${CT_RAM} \
  --swap 256 \
  --rootfs ${STORAGE}:${CT_DISK} \
  --net0 name=eth0,bridge=${CT_BRIDGE},ip=dhcp \
  --unprivileged 1 \
  --features nesting=1 \
  --start 1

success "Container ${CT_ID} created and started"

# Wait for network
info 'Waiting for network...'
sleep 5

# Install Node.js 20 and git
info 'Installing Node.js 20...'
pct exec ${CT_ID} -- bash -c '
  apt-get update -qq
  apt-get install -y -qq curl git ca-certificates
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 
  apt-get install -y -qq nodejs
  node --version
'
success 'Node.js installed'

# Clone repository
info 'Cloning DiscoLauncher-backend...'
pct exec ${CT_ID} -- bash -c '
  git clone https://github.com/varrimain/DiscoLauncher-backend.git /opt/discolauncher-backend
  cd /opt/discolauncher-backend
  npm install --omit=dev
'
success 'Repository cloned'

# Create .env
pct exec ${CT_ID} -- bash -c "cat > /opt/discolauncher-backend/.env << 'ENVEOF'
ADMIN_PORT=5000
LAUNCHER_PORT=6500
JWT_SECRET=${CT_JWT}
ADMIN_USER=admin
ADMIN_PASS=${CT_ADMIN_PASS}
ENVEOF"

# Create systemd service
pct exec ${CT_ID} -- bash -c "cat > /etc/systemd/system/discolauncher.service << 'SVCEOF'
[Unit]
Description=DiscoLauncher Backend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/discolauncher-backend
EnvironmentFile=/opt/discolauncher-backend/.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF"

pct exec ${CT_ID} -- bash -c 'systemctl daemon-reload && systemctl enable discolauncher && systemctl start discolauncher'
success 'Service started'

# Get container IP
CT_IP=$(pct exec ${CT_ID} -- hostname -I | awk '{print $1}')

echo ''
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     DiscoLauncher Backend installed! 🎉       ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ''
echo -e "  Admin Panel:    ${CYAN}http://${CT_IP}:5000${NC}"
echo -e "  Launcher API:   ${CYAN}http://${CT_IP}:6500${NC}"
echo -e "  Admin user:     ${YELLOW}admin${NC}"
echo -e "  Admin password: ${YELLOW}${CT_ADMIN_PASS}${NC}"
echo ''
echo -e "  Next step: Set Launcher API URL in DiscoLauncher Settings:"
echo -e "  ${CYAN}http://${CT_IP}:6500${NC}"
echo ''
warn 'Save your credentials! The password is not shown again.'
