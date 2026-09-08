# Proxmox LXC Installation Guide

This guide covers everything you need to know to install and manage DiscoLauncher Backend on Proxmox VE using the automated installer script.

---

## Prerequisites

- **Proxmox VE 7.x or 8.x** installed on a physical or virtual host
- **Internet access** from the Proxmox host (to download the template and clone the repository)
- At least **512 MB RAM** and **4 GB disk** available for the container
- Shell access to the Proxmox host (via the web UI console or SSH)

---

## One-Command Install

Open the **Proxmox VE host shell** (not inside a VM or container) and run:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Varringard/DiscoLauncher-backend/main/install.sh)
```

Or, if you prefer to review the script first:

```bash
# Download
curl -fsSL https://raw.githubusercontent.com/Varringard/DiscoLauncher-backend/main/install.sh -o install.sh

# Review
cat install.sh

# Run
bash install.sh
```

---

## Interactive Configuration

The installer will ask you several questions. Press **Enter** to accept the default value shown in brackets.

```
Container ID [200]:         # LXC container ID (must be unique)
Container name [discolauncher]:  # Hostname for the container
RAM (MB) [512]:             # Memory allocation
Disk size (GB) [4]:         # Root filesystem size
Bridge [vmbr0]:             # Network bridge (usually vmbr0)
Admin password [admin123]:  # Password for the admin panel
JWT secret [auto-generate]: # Secret for JWT signing (leave blank to auto-generate)
```

---

## What the Script Does — Step by Step

### Step 1: Validate Environment

The script checks that `pct` (Proxmox Container Tools) is available, confirming it's running on a Proxmox host.

### Step 2: Detect Storage

Automatically detects the available Proxmox storage pools for container rootfs and LXC templates.

### Step 3: Download Debian 12 Template

If the Debian 12 LXC template is not already cached, the script downloads it via `pveam`:

```bash
pveam update
pveam download local debian-12-standard_12.x_amd64.tar.zst
```

### Step 4: Create the LXC Container

Creates an unprivileged container with:
- DHCP networking on the specified bridge
- `nesting=1` feature enabled (required for some Node.js operations)
- 256 MB swap in addition to the configured RAM

### Step 5: Install Node.js 20

Inside the container:
```bash
apt-get update && apt-get install -y curl git ca-certificates
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs
```

### Step 6: Clone Repository & Install Dependencies

```bash
git clone https://github.com/Varringard/DiscoLauncher-backend.git /opt/discolauncher-backend
cd /opt/discolauncher-backend
npm install --omit=dev
```

### Step 7: Create `.env` Configuration

Writes `/opt/discolauncher-backend/.env` with your chosen admin password and JWT secret.

### Step 8: Create systemd Service

Creates `/etc/systemd/system/discolauncher.service` and enables it to start automatically on boot:

```ini
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
```

### Step 9: Print Summary

Displays the container IP address, admin panel URL, and credentials.

---

## Post-Installation Configuration

### Access the Container Shell

```bash
pct enter <CT_ID>
```

### Edit Configuration

```bash
nano /opt/discolauncher-backend/.env
```

After editing, restart the service:

```bash
systemctl restart discolauncher
```

### Change Admin Password

Edit `.env` and update `ADMIN_PASS`, then restart:

```bash
sed -i 's/^ADMIN_PASS=.*/ADMIN_PASS=mynewpassword/' /opt/discolauncher-backend/.env
systemctl restart discolauncher
```

### Set a Static IP (Optional)

By default, the container uses DHCP. To set a static IP, on the **Proxmox host**:

```bash
pct set <CT_ID> --net0 name=eth0,bridge=vmbr0,ip=192.168.1.50/24,gw=192.168.1.1
pct reboot <CT_ID>
```

---

## Firewall / Network Setup

### Ports Required

| Port | Protocol | Purpose |
|---|---|---|
| `5000` | TCP | Admin Panel API |
| `6500` | TCP | Launcher API (used by DiscoLauncher client) |

### Proxmox Firewall

If you have the Proxmox firewall enabled, allow these ports on the container:

In the Proxmox web UI: **Datacenter → \<node\> → CT \<id\> → Firewall → Add rule**

Or via CLI on the host:

```bash
# Allow admin panel
pvesh create /nodes/$(hostname)/lxc/<CT_ID>/firewall/rules \
  --action ACCEPT --type in --proto tcp --dport 5000 --enable 1

# Allow launcher API
pvesh create /nodes/$(hostname)/lxc/<CT_ID>/firewall/rules \
  --action ACCEPT --type in --proto tcp --dport 6500 --enable 1
```

### UFW (Inside the Container)

If you install UFW inside the container:

```bash
ufw allow 5000/tcp
ufw allow 6500/tcp
ufw enable
```

### Reverse Proxy (Recommended for HTTPS)

For production, put the backend behind **nginx** or **Caddy** with SSL:

**nginx example:**
```nginx
server {
    listen 443 ssl;
    server_name api.yourlauncherdomain.com;

    ssl_certificate /etc/letsencrypt/live/api.yourlauncherdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourlauncherdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:6500;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Updating

### Using the update script (from Proxmox host)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Varringard/DiscoLauncher-backend/main/update.sh)
# Prompts for container ID, then pulls latest and restarts
```

Or with container ID as argument:

```bash
bash update.sh 200
```

### Manual update (inside container)

```bash
cd /opt/discolauncher-backend
git pull --ff-only
npm install --omit=dev
systemctl restart discolauncher
```

---

## Backup

### Proxmox Built-in Backup (Recommended)

Use the Proxmox web UI: **Datacenter → Backup → Add** and include the container.

Or via CLI:

```bash
vzdump <CT_ID> --storage local --compress zstd
```

### Manual Data Backup

The important data is in `/opt/discolauncher-backend/data/`:

```bash
# From Proxmox host
pct exec <CT_ID> -- tar czf /tmp/discolauncher-backup.tar.gz /opt/discolauncher-backend/data
pct pull <CT_ID> /tmp/discolauncher-backup.tar.gz ./discolauncher-backup-$(date +%Y%m%d).tar.gz
```

---

## Troubleshooting

### Service won't start

Check the logs:
```bash
pct exec <CT_ID> -- journalctl -u discolauncher -n 100 --no-pager
```

Common causes:
- Missing `.env` file — run `cp .env.example .env` and fill in values
- Port already in use — check with `ss -tlnp | grep 5000`
- Node.js not found — verify with `which node` inside the container

### Container won't start

```bash
pct start <CT_ID>
# Check status
pct status <CT_ID>
```

Check host logs:
```bash
journalctl -u pve-guests -n 50 --no-pager
```

### Can't connect to admin panel

1. Verify the service is running: `pct exec <CT_ID> -- systemctl status discolauncher`
2. Check the container IP: `pct exec <CT_ID> -- hostname -I`
3. Verify the port is listening: `pct exec <CT_ID> -- ss -tlnp | grep 5000`
4. Check firewall rules on both the Proxmox host and container

### npm install fails

Usually a network issue inside the container:

```bash
pct exec <CT_ID> -- ping -c 3 registry.npmjs.org
# If no network, check DNS:
pct exec <CT_ID> -- cat /etc/resolv.conf
# Add a DNS server if missing:
pct exec <CT_ID> -- bash -c 'echo "nameserver 1.1.1.1" > /etc/resolv.conf'
```

### git clone fails

Check connectivity:
```bash
pct exec <CT_ID> -- curl -I https://github.com
```

If GitHub is unreachable, check your network bridge and gateway settings.

---

## Uninstalling

To completely remove the container:

```bash
pct stop <CT_ID>
pct destroy <CT_ID>
```

> ⚠️ This permanently deletes the container and all its data. Make a backup first!
