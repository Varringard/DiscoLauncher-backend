<div align="center">

```
 ____  _           _                            _              
|  _ \(_)___  ___ | |    __ _ _   _ _ __   ___| |__   ___ _ __
| | | | / __|/ __|| |   / _` | | | | '_ \ / __| '_ \ / _ \ '__|
| |_| | \__ \ (__ | |__| (_| | |_| | | | | (__| | | |  __/ |  
|____/|_|___/\___||_____\__,_|\__,_|_| |_|\___|_| |_|\___|_|  
```

**DiscoLauncher Backend** — Open source Minecraft launcher API server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org/)
[![Proxmox](https://img.shields.io/badge/Proxmox-VE-orange.svg)](https://www.proxmox.com/)

</div>

---

## Overview

DiscoLauncher Backend is the server-side component of the **DiscoLauncher** ecosystem — an open source Minecraft launcher. It provides a REST API for the launcher client, an admin panel for server administrators, player authentication, mod synchronization, and optional integration with **DiscoPanel** for automated server management.

The backend is designed to run in a **Proxmox LXC container** (lightweight, low resource usage), but can also be deployed manually on any Linux or Windows machine.

---

## ✨ Features

- 🔐 **Player Authentication** — Register/login with JWT tokens, bcrypt password hashing
- 🖥️ **Admin Panel API** — Manage servers, mods, settings from a secure admin interface
- 🗂️ **Server Management** — Multiple Minecraft servers with per-server mod lists
- 📦 **Mod Sync** — Upload and manage client-side mods per server
- 🔗 **DiscoPanel Integration** — Auto-sync servers and configurations from DiscoPanel
- 🚀 **One-command Proxmox Install** — Automated LXC container setup script
- 🪶 **Lightweight** — Runs comfortably on 512 MB RAM, 4 GB disk
- 💾 **SQLite** — Zero-config embedded database, no PostgreSQL/MySQL needed

---

## 🚀 Quick Install (Proxmox)

Run this on your **Proxmox VE host shell**:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Varringard/DiscoLauncher-backend/main/install.sh)
```

The script will:
1. Prompt you for container settings (ID, name, RAM, disk, bridge)
2. Download the Debian 12 LXC template if needed
3. Create and start the LXC container
4. Install Node.js 20 inside the container
5. Clone this repository and install dependencies
6. Set up a systemd service for auto-start
7. Print the admin panel URL and credentials

> **Requirements:** Proxmox VE 7.x or 8.x, internet access from the host.

---

## 🛠️ Manual Install

See [docs/MANUAL_INSTALL.md](docs/MANUAL_INSTALL.md) for instructions on:
- Ubuntu/Debian
- Windows
- Running with PM2 or as a Windows Service

---

## 🖥️ Admin Panel

The admin panel runs on port **5000** by default. It exposes a JSON API consumed by your admin frontend (e.g., DiscoLauncher Admin web app).

### What you can manage:

| Feature | Description |
|---|---|
| **Servers** | Add, edit, and remove Minecraft servers |
| **Mods** | Upload/delete client mods per server |
| **Public Host** | Set the public IP/domain for each server |
| **DiscoPanel Sync** | Connect to DiscoPanel and toggle auto-sync |
| **Player Accounts** | View registered players |
| **Config** | Update JWT secret, admin credentials, ports |

### Default Credentials

| Setting | Default |
|---|---|
| Admin user | `admin` |
| Admin password | `admin123` (set during install) |
| Admin port | `5000` |
| Launcher API port | `6500` |

> ⚠️ **Always change the default password and JWT secret before exposing to the internet!**

---

## 📡 API Endpoints Summary

### Launcher API (port 6500)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/servers` | List all servers with online status |
| `GET` | `/api/servers/:id/manifest` | Mod manifest for client sync |
| `GET` | `/api/servers/:id/mods` | List mods for a server |
| `POST` | `/api/auth/login` | Player login |
| `POST` | `/api/auth/register` | Player registration |

### Admin API (port 5000)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/admin/sync-api` | Trigger DiscoPanel sync |
| `POST` | `/api/admin/config` | Update backend settings |
| `POST` | `/api/admin/servers/:id/upload-mod` | Upload a client mod |
| `POST` | `/api/admin/servers/:id/delete-mod` | Delete a client mod |
| `POST` | `/api/admin/servers/:id/public-host` | Set server public host |
| `POST` | `/api/admin/servers/:id/toggle-sync` | Toggle DiscoPanel sync |

Full API documentation: [docs/API.md](docs/API.md)

---

## 🔄 Updating

### Proxmox (recommended)

Run on your Proxmox host:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Varringard/DiscoLauncher-backend/main/update.sh)
# Or if you've cloned this repo:
bash update.sh [CONTAINER_ID]
```

### Manual

```bash
cd /opt/discolauncher-backend
git pull --ff-only
npm install --omit=dev
systemctl restart discolauncher
```

---

## 🔗 DiscoPanel Integration

DiscoPanel is an optional companion panel that manages your Minecraft servers. DiscoLauncher Backend can connect to DiscoPanel to automatically sync server lists, mod packs, and version info.

See [docs/DISCOPANEL_SETUP.md](docs/DISCOPANEL_SETUP.md) for setup instructions.

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and adjust:

```bash
cp .env.example .env
nano .env
```

| Variable | Default | Description |
|---|---|---|
| `ADMIN_PORT` | `5000` | Port for the admin API |
| `LAUNCHER_PORT` | `6500` | Port for the launcher API |
| `JWT_SECRET` | *(required)* | Secret for signing JWT tokens |
| `ADMIN_USER` | `admin` | Admin username |
| `ADMIN_PASS` | `changeme` | Admin password |
| `DATA_DIR` | `./data` | Directory for database and uploads |

---

## 📁 Project Structure

```
DiscoLauncher-backend/
├── server.js               # Entry point — starts both Express servers
├── package.json
├── .env.example            # Environment variable template
├── install.sh              # Proxmox LXC one-command installer
├── update.sh               # Proxmox update script
├── docs/
│   ├── API.md              # Full API reference
│   ├── PROXMOX_INSTALL.md  # Detailed Proxmox setup guide
│   ├── DISCOPANEL_SETUP.md # DiscoPanel integration guide
│   └── MANUAL_INSTALL.md  # Manual install (Ubuntu, Windows, PM2)
└── data/                   # Runtime data (gitignored)
    ├── discolauncher.db    # SQLite database
    └── uploads/            # Uploaded client mods
```

---

## 🌐 Network Ports

| Port | Service | Who connects |
|---|---|---|
| `5000` | Admin Panel API | Your admin browser / admin app |
| `6500` | Launcher API | DiscoLauncher client app |

Make sure these ports are accessible from the respective clients. See [docs/PROXMOX_INSTALL.md](docs/PROXMOX_INSTALL.md) for firewall setup.

---

## 🐛 Troubleshooting

**Service won't start:**
```bash
pct exec <CT_ID> -- journalctl -u discolauncher -n 50 --no-pager
```

**Check service status:**
```bash
pct exec <CT_ID> -- systemctl status discolauncher
```

**Restart service:**
```bash
pct exec <CT_ID> -- systemctl restart discolauncher
```

More troubleshooting tips in [docs/PROXMOX_INSTALL.md](docs/PROXMOX_INSTALL.md).

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Open a Pull Request

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

Made with ❤️ by the DiscoLauncher community

</div>
