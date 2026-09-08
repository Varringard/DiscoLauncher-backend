# DiscoPanel Integration Guide

## What is DiscoPanel?

**DiscoPanel** is a Minecraft server management panel (similar to Pterodactyl) used to manage game servers. DiscoLauncher Backend can connect to your DiscoPanel instance to automatically import and synchronize server information — so you don't have to manually enter server names, versions, and mod lists in two separate places.

> **DiscoPanel integration is optional.** If you don't use DiscoPanel, you can manage everything directly through the DiscoLauncher Backend admin API. See the section [Running Without DiscoPanel](#running-without-discopanel) below.

---

## Getting the API Token from DiscoPanel

1. Log into your **DiscoPanel** web interface as an administrator.
2. Navigate to **Account Settings** (top-right menu → Account).
3. Scroll to the **API Credentials** section.
4. Click **Create New** (or **Generate Token**).
5. Give the token a descriptive name, e.g. `DiscoLauncher Backend`.
6. Copy the token — it will only be shown **once**.

> The token typically looks like: `ptlc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

---

## Configuring the Connection in the Admin Panel

Once you have the token, configure the connection via the admin API:

### Using curl

```bash
# First, log in to get an admin token
curl -s -X POST http://<host>:5000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}' | jq .token

# Then trigger sync with your DiscoPanel details
curl -s -X POST http://<host>:5000/api/admin/sync-api \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "discoPanelUrl": "https://panel.example.com",
    "discoPanelToken": "ptlc_xxxxxxxxxxxxxxxx"
  }'
```

### Using the Admin Panel UI

If you're using the DiscoLauncher Admin web interface:

1. Open **Settings → DiscoPanel**.
2. Enter the **Panel URL** (e.g., `https://panel.example.com`).
3. Enter the **API Token**.
4. Click **Save & Sync**.

The URL and token are saved in the database and used for all future syncs.

---

## What Gets Synced

When a sync is triggered, the backend connects to DiscoPanel and imports:

| Data | Source | Notes |
|---|---|---|
| Server name | DiscoPanel server name | |
| Server description | DiscoPanel description | |
| Game version | DiscoPanel startup variable `MINECRAFT_VERSION` | |
| Modloader type | DiscoPanel startup variable `MOD_LOADER` | e.g., `fabric`, `forge`, `vanilla` |
| Modloader version | DiscoPanel startup variable `MOD_LOADER_VERSION` | |
| Public IP / domain | DiscoPanel allocation | The IP players connect to |
| Public port | DiscoPanel allocation port | |

**Mods are NOT synced from DiscoPanel** — mod JAR files for the launcher client are managed separately through the DiscoLauncher Backend admin panel. This is because DiscoPanel manages server-side mods, while DiscoLauncher Backend manages the **client-side** mods that get synced to players.

---

## Enabling / Disabling Sync Per Server

You can control whether each server participates in DiscoPanel sync:

```bash
# Enable sync for server ID 1
curl -X POST http://<host>:5000/api/admin/servers/1/toggle-sync \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"syncEnabled": true}'

# Disable sync for server ID 2
curl -X POST http://<host>:5000/api/admin/servers/2/toggle-sync \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"syncEnabled": false}'
```

When sync is **disabled** for a server, its data (name, version, host, etc.) won't be overwritten by future syncs, allowing manual overrides.

---

## Triggering Manual Sync

To re-sync at any time (for example, after adding a new server in DiscoPanel):

```bash
curl -X POST http://<host>:5000/api/admin/sync-api \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Sending an empty body re-uses the previously saved DiscoPanel URL and token.

---

## Troubleshooting Sync Issues

### `502 Bad Gateway — Failed to reach DiscoPanel`

- Verify the panel URL is correct and reachable from the backend server.
- Test connectivity from inside the LXC container:
  ```bash
  curl -I https://panel.example.com
  ```
- Check that the panel URL does **not** have a trailing slash.

### `401 Unauthorized` from DiscoPanel

- The API token is incorrect or has been revoked.
- Generate a new token in DiscoPanel and re-run the sync configuration.

### Servers not appearing after sync

- Check that the servers are **not in a suspended state** in DiscoPanel.
- Ensure the API token has permission to list all servers (use an admin token, not a user token).
- Check the backend logs:
  ```bash
  journalctl -u discolauncher -n 50 --no-pager
  ```

### Sync succeeds but version shows as "unknown"

- DiscoPanel startup variables `MINECRAFT_VERSION`, `MOD_LOADER`, and `MOD_LOADER_VERSION` may not be set for those servers.
- Set them in **DiscoPanel → Server → Startup** and re-sync.

---

## Running Without DiscoPanel

You can use DiscoLauncher Backend without DiscoPanel by managing servers manually:

### Adding a server manually

```bash
# POST to create a server (replace with actual admin API endpoint)
curl -X POST http://<host>:5000/api/admin/servers \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Survival Server",
    "description": "Classic survival experience",
    "publicHost": "play.example.com",
    "publicPort": 25565,
    "version": "1.20.1",
    "modloader": "fabric",
    "modloaderVersion": "0.15.11"
  }'
```

### Uploading client mods manually

```bash
curl -X POST http://<host>:5000/api/admin/servers/1/upload-mod \
  -H "Authorization: Bearer <admin-token>" \
  -F "mod=@./sodium-0.5.8.jar"
```

All other features (player auth, skin hosting, mod sync to clients) work exactly the same whether or not DiscoPanel is configured.
