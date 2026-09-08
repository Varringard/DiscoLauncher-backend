# API Reference — DiscoLauncher Backend

This document describes all REST API endpoints exposed by the DiscoLauncher Backend.

---

## Base URLs

| Service | Default Port | Base URL |
|---|---|---|
| Launcher API | `6500` | `http://<host>:6500` |
| Admin API | `5000` | `http://<host>:5000` |

---

## Authentication

### Player Authentication (Launcher API)

Player endpoints that require authentication use a **Bearer JWT token** in the `Authorization` header:

```
Authorization: Bearer <token>
```

The token is obtained via `POST /api/auth/login`.

### Admin Authentication (Admin API)

Admin endpoints use a separate **admin JWT token** obtained via `POST /api/admin/login`.

---

## Launcher API (Port 6500)

### Servers

---

#### `GET /api/servers`

Returns a list of all enabled Minecraft servers with their online player count.

**Auth required:** No

**Response `200 OK`:**
```json
[
  {
    "id": 1,
    "name": "Survival",
    "description": "Classic survival server",
    "publicHost": "play.example.com",
    "publicPort": 25565,
    "version": "1.20.1",
    "modloader": "fabric",
    "modloaderVersion": "0.15.11",
    "onlineCount": 12,
    "maxPlayers": 100,
    "syncEnabled": true
  }
]
```

---

#### `GET /api/servers/:id/manifest`

Returns the mod manifest for a specific server. The launcher uses this to determine which mods to download or remove from the client.

**Auth required:** No

**Parameters:**
- `id` — Server ID (integer)

**Response `200 OK`:**
```json
{
  "serverId": 1,
  "serverName": "Survival",
  "version": "1.20.1",
  "modloader": "fabric",
  "modloaderVersion": "0.15.11",
  "mods": [
    {
      "id": 42,
      "filename": "sodium-0.5.8.jar",
      "size": 1048576,
      "sha256": "a1b2c3d4e5f6...",
      "downloadUrl": "http://<host>:6500/mods/1/sodium-0.5.8.jar"
    }
  ]
}
```

**Response `404 Not Found`:**
```json
{ "error": "Server not found" }
```

---

#### `GET /api/servers/:id/mods`

Returns the list of mods for a server (without manifest metadata).

**Auth required:** No

**Parameters:**
- `id` — Server ID (integer)

**Response `200 OK`:**
```json
[
  {
    "id": 42,
    "filename": "sodium-0.5.8.jar",
    "size": 1048576,
    "uploadedAt": "2025-01-15T10:30:00Z"
  }
]
```

---

### Player Authentication

---

#### `POST /api/auth/login`

Authenticate a player and receive a JWT token.

**Auth required:** No

**Request body:**
```json
{
  "username": "Steve",
  "password": "mypassword"
}
```

**Response `200 OK`:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "player": {
    "id": 1,
    "username": "Steve",
    "uuid": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

**Response `401 Unauthorized`:**
```json
{ "error": "Invalid username or password" }
```

---

#### `POST /api/auth/register`

Register a new player account.

**Auth required:** No

**Request body:**
```json
{
  "username": "Steve",
  "password": "mypassword",
  "email": "steve@example.com"
}
```

**Constraints:**
- `username`: 3–16 characters, alphanumeric + underscore
- `password`: minimum 6 characters
- `email`: optional but must be valid if provided

**Response `201 Created`:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "player": {
    "id": 2,
    "username": "Steve",
    "uuid": "550e8400-e29b-41d4-a716-446655440001"
  }
}
```

**Response `409 Conflict`:**
```json
{ "error": "Username already taken" }
```

---

## Admin API (Port 5000)

All admin endpoints require admin authentication.

### Admin Login

---

#### `POST /api/admin/login`

Authenticate as admin.

**Auth required:** No

**Request body:**
```json
{
  "username": "admin",
  "password": "yourpassword"
}
```

**Response `200 OK`:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response `401 Unauthorized`:**
```json
{ "error": "Invalid credentials" }
```

---

### Configuration

---

#### `POST /api/admin/config`

Update backend settings. Changes are persisted to `.env` and take effect on the next restart (or immediately for non-critical settings).

**Auth required:** Yes (admin token)

**Request body (all fields optional):**
```json
{
  "adminUser": "admin",
  "adminPass": "newpassword",
  "jwtSecret": "my-new-secret-string"
}
```

**Response `200 OK`:**
```json
{ "message": "Config updated. Restart the service for all changes to take effect." }
```

---

### DiscoPanel Sync

---

#### `POST /api/admin/sync-api`

Configure the DiscoPanel connection and trigger an immediate sync of servers.

**Auth required:** Yes (admin token)

**Request body:**
```json
{
  "discoPanelUrl": "https://panel.example.com",
  "discoPanelToken": "ptlc_xxxxxxxxxxxxxxxx"
}
```

**Response `200 OK`:**
```json
{
  "message": "Sync complete",
  "serversImported": 3,
  "serversUpdated": 1
}
```

**Response `502 Bad Gateway`:**
```json
{ "error": "Failed to reach DiscoPanel: connection refused" }
```

---

### Server Management

---

#### `POST /api/admin/servers/:id/upload-mod`

Upload a client-side mod JAR file to a server's mod list.

**Auth required:** Yes (admin token)

**Parameters:**
- `id` — Server ID

**Request:** `multipart/form-data`
- `mod` — `.jar` file

**Response `201 Created`:**
```json
{
  "id": 43,
  "filename": "lithium-0.12.1.jar",
  "size": 524288,
  "sha256": "f1e2d3c4b5a6...",
  "uploadedAt": "2025-01-15T12:00:00Z"
}
```

**Response `400 Bad Request`:**
```json
{ "error": "Only .jar files are allowed" }
```

---

#### `POST /api/admin/servers/:id/delete-mod`

Delete a mod from a server's mod list.

**Auth required:** Yes (admin token)

**Parameters:**
- `id` — Server ID

**Request body:**
```json
{
  "modId": 43
}
```

**Response `200 OK`:**
```json
{ "message": "Mod deleted" }
```

**Response `404 Not Found`:**
```json
{ "error": "Mod not found" }
```

---

#### `POST /api/admin/servers/:id/public-host`

Set the public-facing hostname/IP and port for a server (what players connect to in the Minecraft client).

**Auth required:** Yes (admin token)

**Parameters:**
- `id` — Server ID

**Request body:**
```json
{
  "publicHost": "play.example.com",
  "publicPort": 25565
}
```

**Response `200 OK`:**
```json
{ "message": "Public host updated" }
```

---

#### `POST /api/admin/servers/:id/toggle-sync`

Enable or disable automatic DiscoPanel sync for a specific server.

**Auth required:** Yes (admin token)

**Parameters:**
- `id` — Server ID

**Request body:**
```json
{
  "syncEnabled": true
}
```

**Response `200 OK`:**
```json
{
  "serverId": 1,
  "syncEnabled": true
}
```

---

## Error Responses

All endpoints return errors in the following format:

```json
{
  "error": "Human-readable error message"
}
```

### HTTP Status Codes

| Code | Meaning |
|---|---|
| `200` | Success |
| `201` | Created |
| `400` | Bad Request — invalid input |
| `401` | Unauthorized — missing or invalid token |
| `403` | Forbidden — insufficient privileges |
| `404` | Not Found |
| `409` | Conflict — duplicate resource |
| `500` | Internal Server Error |
| `502` | Bad Gateway — upstream service (DiscoPanel) unreachable |

---

## Rate Limiting

Currently no rate limiting is implemented by default. It is strongly recommended to put the backend behind a reverse proxy (nginx, Caddy) with rate limiting configured if exposing to the public internet.

---

## Versioning

The API does not currently use a versioned path prefix (e.g., `/v1/`). Breaking changes will be documented in the [CHANGELOG](../CHANGELOG.md).
