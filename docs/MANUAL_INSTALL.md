# Manual Installation Guide

This guide covers installing DiscoLauncher Backend on a server **without Proxmox** — directly on Ubuntu/Debian Linux, or on Windows — and running it as a persistent service.

---

## Ubuntu / Debian

### Prerequisites

- Ubuntu 20.04+ or Debian 11+
- Root or sudo access
- Git
- Node.js 20+

### Step 1: Install Node.js 20

```bash
# Install curl if not present
sudo apt-get update && sudo apt-get install -y curl git

# Add NodeSource repository for Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -

# Install Node.js
sudo apt-get install -y nodejs

# Verify
node --version   # should print v20.x.x
npm --version
```

### Step 2: Clone the Repository

```bash
sudo git clone https://github.com/Varringard/DiscoLauncher-backend.git /opt/discolauncher-backend
cd /opt/discolauncher-backend
```

### Step 3: Install Dependencies

```bash
sudo npm install --omit=dev
```

### Step 4: Configure Environment

```bash
sudo cp .env.example .env
sudo nano .env
```

Set at minimum:

```env
ADMIN_PORT=5000
LAUNCHER_PORT=6500
JWT_SECRET=your-long-random-secret-here
ADMIN_USER=admin
ADMIN_PASS=yourpassword
```

Generate a secure JWT secret:

```bash
openssl rand -hex 32
```

### Step 5: Test Run

```bash
cd /opt/discolauncher-backend
node server.js
```

You should see output like:

```
[DiscoLauncher] Admin API listening on port 5000
[DiscoLauncher] Launcher API listening on port 6500
```

Press `Ctrl+C` to stop.

---

## Running as a systemd Service (Ubuntu/Debian)

### Create the Service File

```bash
sudo nano /etc/systemd/system/discolauncher.service
```

Paste the following:

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
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable discolauncher
sudo systemctl start discolauncher
```

### Check Status

```bash
sudo systemctl status discolauncher
sudo journalctl -u discolauncher -f   # follow logs
```

---

## Running with PM2 (Alternative to systemd)

[PM2](https://pm2.keymetrics.io/) is a Node.js process manager that works on both Linux and Windows.

### Install PM2

```bash
sudo npm install -g pm2
```

### Start with PM2

```bash
cd /opt/discolauncher-backend
pm2 start server.js --name discolauncher
pm2 save
pm2 startup   # generates the command to run for auto-start on boot — run it as instructed
```

### Useful PM2 Commands

```bash
pm2 status              # list all managed processes
pm2 logs discolauncher  # view logs
pm2 restart discolauncher
pm2 stop discolauncher
pm2 delete discolauncher
```

---

## Windows

### Prerequisites

- Windows 10/11 or Windows Server 2019+
- [Node.js 20 LTS](https://nodejs.org/) installed
- Git for Windows

### Step 1: Install Node.js

Download and run the installer from https://nodejs.org/en/download — choose the **LTS (20.x)** version.

Verify in a new Command Prompt or PowerShell:

```powershell
node --version
npm --version
```

### Step 2: Clone the Repository

```powershell
git clone https://github.com/Varringard/DiscoLauncher-backend.git C:\discolauncher-backend
cd C:\discolauncher-backend
```

### Step 3: Install Dependencies

```powershell
npm install --omit=dev
```

### Step 4: Configure Environment

```powershell
Copy-Item .env.example .env
notepad .env
```

Set your values as described in the Ubuntu section above.

### Step 5: Test Run

```powershell
node server.js
```

### Step 6: Run as Windows Service with PM2

```powershell
npm install -g pm2
npm install -g pm2-windows-startup

cd C:\discolauncher-backend
pm2 start server.js --name discolauncher
pm2 save
pm2-startup install
```

### Alternative: NSSM (Non-Sucking Service Manager)

1. Download [NSSM](https://nssm.cc/download)
2. Open an elevated Command Prompt
3. Run:
   ```cmd
   nssm install DiscoLauncher
   ```
4. In the GUI that opens:
   - **Path:** `C:\Program Files\nodejs\node.exe`
   - **Startup directory:** `C:\discolauncher-backend`
   - **Arguments:** `server.js`
5. Go to the **Environment** tab and add your env vars (or point NSSM to your `.env` file)
6. Click **Install service**
7. Start via Services (`services.msc`) or:
   ```cmd
   nssm start DiscoLauncher
   ```

---

## Environment Variables Reference

All configuration is via environment variables (loaded from `.env`):

| Variable | Required | Default | Description |
|---|---|---|---|
| `ADMIN_PORT` | No | `5000` | Port for the Admin Panel API |
| `LAUNCHER_PORT` | No | `6500` | Port for the Launcher API |
| `JWT_SECRET` | **Yes** | — | Secret key for signing JWT tokens. Use a long random string. |
| `ADMIN_USER` | No | `admin` | Admin login username |
| `ADMIN_PASS` | **Yes** | — | Admin login password |
| `DATA_DIR` | No | `./data` | Path to the data directory (database + uploads) |

### Generating a Secure JWT Secret

**Linux/macOS:**
```bash
openssl rand -hex 32
```

**Windows PowerShell:**
```powershell
[System.Web.Security.Membership]::GeneratePassword(64, 0)
# Or:
-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | % {[char]$_})
```

---

## Data Directory Layout

By default, runtime data is stored in `./data/` (relative to the repository root):

```
data/
├── discolauncher.db    # SQLite database (players, servers, mods)
└── uploads/
    └── mods/           # Uploaded mod JAR files (per server)
        └── 1/          # Server ID subdirectory
```

To use a custom data directory, set `DATA_DIR` in `.env`:

```env
DATA_DIR=/var/lib/discolauncher
```

---

## Updating (Manual)

```bash
cd /opt/discolauncher-backend     # or your install path
git pull --ff-only
npm install --omit=dev
systemctl restart discolauncher   # or: pm2 restart discolauncher
```

On Windows with PM2:
```powershell
cd C:\discolauncher-backend
git pull
npm install --omit=dev
pm2 restart discolauncher
```
