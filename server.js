// Load environment variables from .env file if present
try { require('dotenv').config(); } catch(e) {}

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const Database = require('better-sqlite3');
const http = require('http');
const os = require('os');
const { execFile } = require('child_process');

// Config & Ports
const ADMIN_PORT = process.env.ADMIN_PORT || 5000;
const LAUNCHER_PORT = process.env.LAUNCHER_PORT || 6500;
let JWT_SECRET = process.env.JWT_SECRET; // Will be loaded from DB if not set

// Admin Credentials
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme';

// Paths
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const SERVERS_DIR = path.join(DATA_DIR, 'servers');

[DATA_DIR, UPLOADS_DIR, SERVERS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// SQLite DB setup
const db = new Database(path.join(DATA_DIR, 'discolauncher.db'));

// Initialize tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    uuid TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    subtitle TEXT,
    version TEXT NOT NULL,
    modloader TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER DEFAULT 25565,
    online INTEGER DEFAULT 0,
    max_online INTEGER DEFAULT 100,
    status TEXT DEFAULT 'online',
    description TEXT,
    total_mods INTEGER DEFAULT 0,
    manifest_url TEXT
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Settings helpers
function getSetting(key, defVal = '') {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : defVal;
}

function setSetting(key, value) {
  db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(key, value);
}

// Parse domain or IP with optional port (default 25565 if port omitted)
function parseHostAndPort(raw, defaultHost = '127.0.0.1', defaultPort = 25565) {
  if (!raw || !raw.trim()) {
    return { host: defaultHost, port: defaultPort, raw: '' };
  }
  const clean = raw.trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  if (clean.includes(':')) {
    const lastColon = clean.lastIndexOf(':');
    const h = clean.substring(0, lastColon).trim();
    const p = parseInt(clean.substring(lastColon + 1).trim(), 10);
    if (!isNaN(p) && p > 0 && p <= 65535) {
      return { host: h || defaultHost, port: p, raw: clean };
    }
  }
  return { host: clean, port: 25565, raw: clean };
}

// Initial DiscoPanel config defaults
if (!getSetting('discopanel_url')) {
  setSetting('discopanel_url', '');
}
if (!getSetting('discopanel_token')) {
  setSetting('discopanel_token', '');
}

// Persistent JWT Secret from DB or ENV (sessions never expire on server restart)
if (!JWT_SECRET) {
  JWT_SECRET = getSetting('jwt_secret');
  if (!JWT_SECRET) {
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
    setSetting('jwt_secret', JWT_SECRET);
  }
}

// Admin credentials helper (supports dynamic update via settings table)
function getAdminCredentials() {
  const username = getSetting('admin_username', ADMIN_USER);
  const passwordHash = getSetting('admin_password_hash', '');
  const plainPassword = getSetting('admin_password', ADMIN_PASS);
  return { username, passwordHash, plainPassword };
}

// Cookie parser helper
function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
  }
  return list;
}

// Admin Auth Middleware
function requireAdminAuth(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies.admin_token || (req.headers.authorization && req.headers.authorization.split(' ')[1]) || req.query.auth_token;

  if (!token) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }
    return res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded && decoded.role === 'admin') {
      req.adminUser = decoded;
      return next();
    }
  } catch (err) {}

  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ success: false, error: 'Session expired' });
  }
  return res.redirect('/login');
}

// Launcher Player Auth Middleware
function authenticatePlayerToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authorization token required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// Multer for client mods uploads
const modStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const srvDir = path.join(SERVERS_DIR, req.params.id, 'mods');
    if (!fs.existsSync(srvDir)) fs.mkdirSync(srvDir, { recursive: true });
    cb(null, srvDir);
  },
  filename: (req, file, cb) => {
    let clean = Buffer.from(file.originalname, 'latin1').toString('utf8');
    clean = path.basename(clean).replace(/[^a-zA-Z0-9_\-\.\+\(\)\[\] ]/g, '_');
    if (!clean.endsWith('.jar')) clean += '.jar';
    cb(null, clean);
  }
});
const modUpload = multer({ storage: modStorage, limits: { fileSize: 350 * 1024 * 1024 } });

// Multer for shaderpacks uploads (.zip)
const shaderStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const srvDir = path.join(SERVERS_DIR, req.params.id, 'shaderpacks');
    if (!fs.existsSync(srvDir)) fs.mkdirSync(srvDir, { recursive: true });
    cb(null, srvDir);
  },
  filename: (req, file, cb) => {
    let clean = Buffer.from(file.originalname, 'latin1').toString('utf8');
    clean = path.basename(clean).replace(/[^a-zA-Z0-9_\-\.\+\(\)\[\] ]/g, '_');
    if (!clean.endsWith('.zip')) clean += '.zip';
    cb(null, clean);
  }
});
const shaderUpload = multer({ storage: shaderStorage, limits: { fileSize: 500 * 1024 * 1024 } });

// Multer for resourcepacks uploads (.zip)
const resourcepackStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const srvDir = path.join(SERVERS_DIR, req.params.id, 'resourcepacks');
    if (!fs.existsSync(srvDir)) fs.mkdirSync(srvDir, { recursive: true });
    cb(null, srvDir);
  },
  filename: (req, file, cb) => {
    let clean = Buffer.from(file.originalname, 'latin1').toString('utf8');
    clean = path.basename(clean).replace(/[^a-zA-Z0-9_\-\.\+\(\)\[\] ]/g, '_');
    if (!clean.endsWith('.zip')) clean += '.zip';
    cb(null, clean);
  }
});
const resourcepackUpload = multer({ storage: resourcepackStorage, limits: { fileSize: 500 * 1024 * 1024 } });

// =========================================================================
// FILE MANAGER HELPERS & STORAGE
// =========================================================================
function resolveSafePath(serverId, subpath = '') {
  if (!serverId || typeof serverId !== 'string') throw new Error('Invalid server ID');
  if (serverId.includes('..') || serverId.includes('/') || serverId.includes('\\')) {
    throw new Error('Invalid server ID');
  }
  const serverRoot = path.resolve(SERVERS_DIR, serverId);
  const normalizedSubpath = path.normalize(subpath || '').replace(/^(\.\.[\/\\])+/, '');
  const targetPath = path.resolve(serverRoot, normalizedSubpath);
  if (!targetPath.startsWith(serverRoot)) {
    throw new Error('Access denied: Path traversal detected');
  }
  return { serverRoot, targetPath, normalizedSubpath };
}

const fmStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      const serverId = req.query.serverId || req.body.serverId;
      const subpath = req.query.subpath || req.body.subpath || '';
      const { targetPath } = resolveSafePath(serverId, subpath);
      if (!fs.existsSync(targetPath)) {
        fs.mkdirSync(targetPath, { recursive: true });
      }
      cb(null, targetPath);
    } catch (err) {
      cb(err);
    }
  },
  filename: (req, file, cb) => {
    let clean = Buffer.from(file.originalname, 'latin1').toString('utf8');
    clean = path.basename(clean).replace(/[\/\\]/g, '_');
    cb(null, clean);
  }
});
const fmUpload = multer({ storage: fmStorage, limits: { fileSize: 1024 * 1024 * 1024 } });

// =========================================================================
// 1. DISCOPANEL API SYNC ENGINE
// =========================================================================


// =========================================================================
// MC SERVER LIST PING (pure Node.js, no deps)
// =========================================================================
const net = require('net');

function mcPing(host, port, timeout) {
  timeout = timeout || 5000;
  return new Promise(function(resolve) {
    var socket = new net.Socket();
    var resolved = false;
    var data = Buffer.alloc(0);
    function done(result) {
      if (resolved) return;
      resolved = true;
      try { socket.destroy(); } catch(e) {}
      resolve(result);
    }
    socket.setTimeout(timeout);
    socket.on('error', function() { done(null); });
    socket.on('timeout', function() { done(null); });
    socket.connect(port, host, function() {
      var hostBuf = Buffer.from(host, 'utf8');
      function encVI(val) {
        var buf = [];
        do {
          var b = val & 0x7F; val >>>= 7;
          if (val !== 0) b |= 0x80; buf.push(b);
        } while (val !== 0);
        return Buffer.from(buf);
      }
      var payload = Buffer.concat([
        Buffer.from([0x00]), encVI(47), encVI(hostBuf.length), hostBuf,
        Buffer.from([(port >> 8) & 0xFF, port & 0xFF]),
        Buffer.from([0x01])
      ]);
      socket.write(Buffer.concat([Buffer.concat([encVI(payload.length), payload]), Buffer.from([0x01, 0x00])]));
    });
    socket.on('data', function(chunk) {
      data = Buffer.concat([data, chunk]);
      try {
        function rdVI(b, o) {
          var r=0, sh=0, sz=0;
          while(true) {
            var x = b[o+sz];
            if (x === undefined) throw new Error('short');
            r |= (x & 0x7F) << sh; sz++;
            if ((x & 0x80) === 0) break; sh += 7;
          }
          return { value: r, size: sz };
        }
        var off = 0;
        var p1 = rdVI(data, off); off += p1.size;
        if (data.length < off + p1.value) return;
        var p2 = rdVI(data, off); off += p2.size;
        if (p2.value !== 0x00) { done(null); return; }
        var p3 = rdVI(data, off); off += p3.size;
        var json = JSON.parse(data.slice(off, off + p3.value).toString('utf8'));
        var pl = json.players || {};
        done({ online: pl.online || 0, max: pl.max || 0 });
      } catch(e) {}
    });
  });
}

var _mcPingCache = {};
var MC_PING_TTL = 10000;

function getCachedMcOnline(ip, port) {
  var key = ip + ':' + port;
  var now = Date.now();
  if (_mcPingCache[key] && now - _mcPingCache[key].ts < MC_PING_TTL) {
    return Promise.resolve(_mcPingCache[key]);
  }
  return mcPing(ip, port, 3000).then(function(r) {
    var info = {
      online: r ? (r.online || 0) : 0,
      max: r ? (r.max || 20) : 20,
      success: !!r
    };
    _mcPingCache[key] = { online: info.online, max: info.max, success: info.success, ts: Date.now() };
    if (r) {
      console.log('[MC Ping] ' + ip + ':' + port + ' -> ' + info.online + '/' + info.max + ' players online');
    }
    return info;
  }).catch(function() {
    return { online: 0, max: 20, success: false };
  });
}

async function queryServerPing(port, dpHost, serverHost) {
  if (dpHost) {
    const res = await getCachedMcOnline(dpHost, port);
    if (res.success) return res;
  }
  if (serverHost && serverHost !== dpHost) {
    const res = await getCachedMcOnline(serverHost, port);
    if (res.success) return res;
  }
  const localRes = await getCachedMcOnline('127.0.0.1', port);
  if (localRes.success) return localRes;

  return { online: 0, max: 20, success: false };
}

// Known server-side only mods that should NOT be distributed to launcher clients by default
const SERVER_ONLY_MOD_PATTERNS = [
  /skinrestorer/i,
  /skinsrestorer/i,
  /^sleep/i,
  /sleepmost/i,
  /harbor/i,
  /^spark/i,
  /placeholder-?api/i,
  /netherportalfix/i,
  /chunky/i,
  /luckperms/i,
  /discordsrv/i,
  /ledger/i,
  /cardboard/i,
  /geyser/i,
  /floodgate/i,
  /fastasyncworldedit/i,
  /coreprotect/i,
  /dynmap/i,
  /bluemap/i,
  /pl3xmap/i
];

function isKnownServerOnlyMod(fileName) {
  if (!fileName) return false;
  return SERVER_ONLY_MOD_PATTERNS.some(pat => pat.test(fileName));
}

async function syncWithDiscoPanelAPI() {
  const dpUrl = getSetting('discopanel_url', 'http://192.168.10.127:8080');
  const dpToken = getSetting('discopanel_token');

  if (!dpToken) throw new Error('DiscoPanel API token not configured!');

  // 1. Fetch servers list via ConnectRPC
  const serversRes = await fetch(`${dpUrl}/discopanel.v1.ServerService/ListServers`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${dpToken}`
    },
    body: JSON.stringify({})
  });

  if (!serversRes.ok) {
    throw new Error(`DiscoPanel API error (${serversRes.status}): ${await serversRes.text()}`);
  }

  const serversData = await serversRes.json();
  const dpServers = serversData.servers || [];
  const syncedServers = [];

  for (const s of dpServers) {
    const srvId = s.id;
    const srvDir = path.join(SERVERS_DIR, srvId);
    const modsDir = path.join(srvDir, 'mods');
    if (!fs.existsSync(modsDir)) fs.mkdirSync(modsDir, { recursive: true });

    // Check if auto-sync of mods from DiscoPanel is enabled for this server
    const isModsSyncEnabled = getSetting('sync_mods_' + srvId, 'true') !== 'false';

    if (isModsSyncEnabled) {
      // 2. Fetch mods list for this server from DiscoPanel
      const modsRes = await fetch(`${dpUrl}/discopanel.v1.ModService/ListMods`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${dpToken}`
        },
        body: JSON.stringify({ serverId: srvId })
      });

      if (modsRes.ok) {
        const modsData = await modsRes.json();
        const mods = modsData.mods || [];
        const dpModFileNames = new Set();

        for (const m of mods) {
          if (!m.enabled) continue;
          dpModFileNames.add(m.fileName);
          const modDest = path.join(modsDir, m.fileName);

          // Download via DiscoPanel File API if not exists or different size
          if (!fs.existsSync(modDest) || fs.statSync(modDest).size !== Number(m.fileSize)) {
            console.log(`Downloading mod ${m.fileName} via DiscoPanel API...`);
            const initRes = await fetch(`${dpUrl}/discopanel.v1.FileService/InitFileDownload`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${dpToken}`
              },
              body: JSON.stringify({ serverId: srvId, path: `mods/${m.fileName}` })
            });

            if (initRes.ok) {
              const initData = await initRes.json();
              const dlRes = await fetch(`${dpUrl}/api/v1/download/${initData.sessionId}`, {
                headers: { 'Authorization': `Bearer ${dpToken}` }
              });

              if (dlRes.ok) {
                const fileBuf = Buffer.from(await dlRes.arrayBuffer());
                fs.writeFileSync(modDest, fileBuf);
              }
            }
          }
        }

        // Save full list of server mods from DiscoPanel
        const dpModsFile = path.join(srvDir, 'dp_mods.json');
        try {
          fs.writeFileSync(dpModsFile, JSON.stringify(Array.from(dpModFileNames), null, 2));
        } catch (e) {}

        // Clean up server-side mods that are no longer in DiscoPanel
        const clientModsFile = path.join(srvDir, 'client_mods.json');
        let clientMods = [];
        try {
          if (fs.existsSync(clientModsFile)) {
            clientMods = JSON.parse(fs.readFileSync(clientModsFile, 'utf8'));
          }
        } catch (e) {}
        const clientModsSet = new Set(clientMods);

        const disabledModsFile = path.join(srvDir, 'disabled_mods.json');
        let disabledMods = [];
        try {
          if (fs.existsSync(disabledModsFile)) {
            disabledMods = JSON.parse(fs.readFileSync(disabledModsFile, 'utf8'));
          }
        } catch (e) {}

        const allLocalMods = fs.existsSync(modsDir) ? fs.readdirSync(modsDir).filter(f => f.endsWith('.jar')) : [];
        let disabledModsChanged = false;
        for (const localMod of allLocalMods) {
          if (!clientModsSet.has(localMod) && !dpModFileNames.has(localMod)) {
            console.log(`[Sync] Deleting obsolete/removed DiscoPanel mod: ${localMod}`);
            try {
              fs.unlinkSync(path.join(modsDir, localMod));
              if (disabledMods.includes(localMod)) {
                disabledMods = disabledMods.filter(f => f !== localMod);
                disabledModsChanged = true;
              }
            } catch (e) {
              console.warn(`[Sync] Failed to unlink ${localMod}:`, e.message);
            }
          }
        }
        // Auto-disable known server-only mods so they are never served to clients by default
        for (const m of mods) {
          if (!m.enabled) continue;
          if (isKnownServerOnlyMod(m.fileName) && !clientModsSet.has(m.fileName)) {
            if (!disabledMods.includes(m.fileName)) {
              disabledMods.push(m.fileName);
              disabledModsChanged = true;
              console.log(`[Sync] Auto-disabling server-only mod from client sync: ${m.fileName}`);
            }
          }
        }

        if (disabledModsChanged) {
          try { fs.writeFileSync(disabledModsFile, JSON.stringify(disabledMods, null, 2)); } catch(e) {}
        }
      }
    } else {
      console.log(`[Sync] DiscoPanel mods sync is disabled for server ${s.name}`);
    }

    // Count client mods
    const clientModsFileForCount = path.join(srvDir, 'client_mods.json');
    let modCount = 0;
    if (fs.existsSync(clientModsFileForCount)) {
      try {
        const cMods = JSON.parse(fs.readFileSync(clientModsFileForCount, 'utf8'));
        modCount = cMods.length;
      } catch (e) {}
    } else if (fs.existsSync(modsDir)) {
      modCount = fs.readdirSync(modsDir).filter(f => f.endsWith('.jar')).length;
    }

    // 3. Update server in SQLite
    const modLoaderClean = (s.modLoader || '').replace('MOD_LOADER_', '').toLowerCase() || 'vanilla';
    const isRunning = s.status === 'SERVER_STATUS_RUNNING';
    let serverHost = '127.0.0.1';
    try { serverHost = new URL(dpUrl).hostname; } catch(e) {}
    let serverPort = s.port || 25565;
    const customHost = getSetting('public_server_host_' + srvId) || getSetting('public_server_host');
    if (customHost && customHost.trim()) {
      const parsed = parseHostAndPort(customHost, serverHost, serverPort);
      serverHost = parsed.host;
      serverPort = parsed.port;
    }

    let realOnline = 0;
    let realMaxOnline = s.maxPlayersSlp || s.maxPlayers || 20;

    // Priority 1: Use DiscoPanel API native playersOnline if available
    if (typeof s.playersOnline === 'number') {
      realOnline = s.playersOnline;
      realMaxOnline = s.maxPlayersSlp || s.maxPlayers || 20;
      console.log(`[Sync] DiscoPanel API reports ${s.name} online: ${realOnline}/${realMaxOnline}`);
    } else {
      // Fallback: Direct TCP ping to Minecraft container
      let dpHost = '127.0.0.1';
      try { dpHost = new URL(dpUrl).hostname; } catch(e) {}
      const pingRes = await queryServerPing(serverPort, dpHost, serverHost);
      realOnline = pingRes.online;
      realMaxOnline = pingRes.max || realMaxOnline;
    }

    db.prepare(`
      INSERT INTO servers (id, name, subtitle, version, modloader, ip, port, online, max_online, status, description, total_mods, manifest_url)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name=excluded.name,
        version=excluded.version,
        modloader=excluded.modloader,
        ip=excluded.ip,
        port=excluded.port,
        online=excluded.online,
        max_online=excluded.max_online,
        status=excluded.status,
        description=excluded.description,
        total_mods=excluded.total_mods,
        manifest_url=excluded.manifest_url
    `).run(
      srvId,
      s.name,
      'DiscoPanel Server',
      s.mcVersion || '1.21.5',
      modLoaderClean,
      serverHost,
      serverPort,
      realOnline,
      realMaxOnline,
      isRunning ? 'online' : 'offline',
      s.description || 'DiscoPanel Game Server',
      modCount,
      `/api/servers/${srvId}/manifest`
    );

    syncedServers.push({ id: srvId, name: s.name, mods: modCount });
  }

  // Remove servers from SQLite that no longer exist in DiscoPanel
  const activeIds = dpServers.map(s => s.id);
  if (activeIds.length > 0) {
    const placeholders = activeIds.map(() => '?').join(',');
    db.prepare(`DELETE FROM servers WHERE id NOT IN (${placeholders})`).run(...activeIds);
  } else {
    db.prepare('DELETE FROM servers').run();
  }

  return { success: true, count: syncedServers.length, servers: syncedServers };
}

// =========================================================================
// 2. LAUNCHER APP (PORT 6500)
// =========================================================================
const launcherApp = express();

launcherApp.use(cors());
launcherApp.use(express.json());
launcherApp.use(express.urlencoded({ extended: true }));
launcherApp.use('/uploads', express.static(UPLOADS_DIR));
launcherApp.use('/files', express.static(SERVERS_DIR));

// Root info
launcherApp.get('/', (req, res) => {
  res.json({
    status: 'online',
    service: 'ExodusWorld Launcher API',
    version: '1.0.0',
    port: LAUNCHER_PORT
  });
});

// Auth Routes (for players)
launcherApp.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });
    if (username.length < 3 || username.length > 16) return res.status(400).json({ error: 'Username length must be between 3 and 16 characters' });

    const existing = db.prepare('SELECT id FROM users WHERE lower(username) = lower(?)').get(username);
    if (existing) return res.status(409).json({ error: 'User with this username already exists' });

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const uuid = crypto.createHash('md5').update(`OfflinePlayer:${username}`).digest('hex');

    const result = db.prepare(`
      INSERT INTO users (username, password_hash, uuid)
      VALUES (?, ?, ?)
    `).run(username, hash, uuid);

    const user = { id: result.lastInsertRowid, username, uuid };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '30d' });

    res.json({ success: true, user, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

launcherApp.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Please enter username and password' });

    const user = db.prepare('SELECT * FROM users WHERE lower(username) = lower(?)').get(username);
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid username or password' });

    const profile = {
      id: user.id,
      username: user.username,
      uuid: user.uuid
    };

    const token = jwt.sign(profile, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, user: profile, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

launcherApp.get('/api/auth/verify', authenticatePlayerToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// Servers & Manifest Routes
launcherApp.get('/api/servers', async (req, res) => {
  const servers = db.prepare('SELECT * FROM servers').all();
  const dpUrlSetting = getSetting('discopanel_url', 'http://192.168.10.127:8080');
  const dpTokenSetting = getSetting('discopanel_token');
  let adminDpHost = '127.0.0.1';
  try { adminDpHost = new URL(dpUrlSetting).hostname; } catch(e) {}

  let adminDpMap = new Map();
  if (dpTokenSetting && dpUrlSetting) {
    try {
      const dpRes = await fetch(`${dpUrlSetting}/discopanel.v1.ServerService/ListServers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${dpTokenSetting}` },
        body: JSON.stringify({}),
        signal: AbortSignal.timeout(2500)
      });
      if (dpRes.ok) {
        const dpData = await dpRes.json();
        (dpData.servers || []).forEach(srv => adminDpMap.set(srv.id, srv));
      }
    } catch(e) {}
  }

  for (const s of servers) {
    const dpSrv = adminDpMap.get(s.id);
    if (dpSrv && typeof dpSrv.playersOnline === 'number') {
      s.online = dpSrv.playersOnline;
      s.max_online = dpSrv.maxPlayersSlp || dpSrv.maxPlayers || s.max_online || 20;
      s.maxOnline = s.max_online;
      s.playerSample = dpSrv.playerSample || [];
      try {
        db.prepare('UPDATE servers SET online = ?, max_online = ? WHERE id = ?').run(s.online, s.max_online, s.id);
      } catch(e) {}
    } else {
      const customHost = getSetting('public_server_host_' + s.id) || getSetting('public_server_host');
      const pInfo = await queryServerPing(s.port || 25565, adminDpHost, customHost || s.ip);
      if (pInfo && pInfo.success) {
        s.online = pInfo.online;
        s.max_online = pInfo.max;
        s.maxOnline = pInfo.max;
        try {
          db.prepare('UPDATE servers SET online = ?, max_online = ? WHERE id = ?').run(s.online, s.max_online, s.id);
        } catch(e) {}
      }
    }
  }
  servers.forEach(s => {
    s.maxOnline = s.max_online || 100;
    s.manifestUrl = s.manifest_url || `/api/servers/${s.id}/manifest`;
    s.totalMods = 0;
    const clientModsPath = path.join(SERVERS_DIR, s.id, 'client_mods.json');
    if (fs.existsSync(clientModsPath)) {
      try {
        const cMods = JSON.parse(fs.readFileSync(clientModsPath, 'utf8'));
        s.totalMods = cMods.length;
      } catch(e) {}
    } else {
      const modsDir = path.join(SERVERS_DIR, s.id, 'mods');
      if (fs.existsSync(modsDir)) {
        s.totalMods = fs.readdirSync(modsDir).filter(f => f.endsWith('.jar')).length;
      }
    }
    s.total_mods = s.totalMods;
    const customHost = getSetting('public_server_host_' + s.id) || getSetting('public_server_host');
    if (customHost && customHost.trim()) {
      const parsed = parseHostAndPort(customHost, s.ip, s.port || 25565);
      s.ip = parsed.host;
      s.port = parsed.port;
    }
  });
  res.json(servers);
});

launcherApp.get('/api/servers/:id/manifest', (req, res) => {
  const serverId = req.params.id;
  const serverDir = path.join(SERVERS_DIR, serverId);

  for (const sub of ['mods', 'config', 'shaderpacks', 'resourcepacks']) {
    const p = path.join(serverDir, sub);
    if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
  }

  const clientModsPath = path.join(serverDir, 'client_mods.json');
  let clientModsSet = new Set();
  try {
    if (fs.existsSync(clientModsPath)) {
      clientModsSet = new Set(JSON.parse(fs.readFileSync(clientModsPath, 'utf8')));
    }
  } catch (e) {}

  const disabledModsPath = path.join(serverDir, 'disabled_mods.json');
  let disabledMods = new Set();
  try {
    if (fs.existsSync(disabledModsPath)) {
      disabledMods = new Set(JSON.parse(fs.readFileSync(disabledModsPath, 'utf8')));
    }
  } catch (e) {}

  function scanDir(currentDir, relativePrefix = '') {
    let result = [];
    if (!fs.existsSync(currentDir)) return result;
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const ent of entries) {
      if (ent.name.startsWith('.') || ent.name === 'client_mods.json' || ent.name === 'disabled_mods.json') continue;
      if (disabledMods.has(ent.name)) continue;
      const fullPath = path.join(currentDir, ent.name);
      const relPath = relativePrefix ? `${relativePrefix}/${ent.name}` : ent.name;
      // Only mods that are explicitly in client_mods.json are sent to launcher clients!
      if (relPath.startsWith('mods/') && !clientModsSet.has(ent.name)) continue;
      if (ent.isDirectory()) {
        result = result.concat(scanDir(fullPath, relPath));
      } else {
        const fileBuf = fs.readFileSync(fullPath);
        const hash = crypto.createHash('sha1').update(fileBuf).digest('hex');
        result.push({
          path: relPath,
          sha1: hash,
          size: fileBuf.length,
          url: `/files/${serverId}/${relPath}`
        });
      }
    }
    return result;
  }

  const files = scanDir(serverDir);
  res.json({ serverId, timestamp: Date.now(), files });
});

// =========================================================================
// 3. ADMIN APP (PORT 5000)
// =========================================================================
const adminApp = express();

adminApp.use(cors());
adminApp.use(express.json());
adminApp.use(express.urlencoded({ extended: true }));
adminApp.use('/uploads', express.static(UPLOADS_DIR));

// Root redirect to /admin
adminApp.get('/', (req, res) => {
  res.redirect('/admin');
});

// Login Page
adminApp.get('/login', (req, res) => {
  const cookies = parseCookies(req);
  const token = cookies.admin_token;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded && decoded.role === 'admin') {
        return res.redirect('/admin');
      }
    } catch (e) {}
  }

  const currentAdminUser = getAdminCredentials().username;
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In - DiscoPanel</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body { background-color: #0b0f19; color: #e2e8f0; font-family: system-ui, -apple-system, sans-serif; }
  </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
  <div class="w-full max-w-md">
    <div class="bg-[#121826] border border-indigo-950/80 rounded-3xl p-8 shadow-2xl relative overflow-hidden">
      <!-- Ambient Glow -->
      <div class="absolute -top-24 -left-24 w-48 h-48 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none"></div>
      <div class="absolute -bottom-24 -right-24 w-48 h-48 bg-purple-600/10 rounded-full blur-3xl pointer-events-none"></div>

      <div class="text-center mb-8 relative">
        <div class="w-16 h-16 rounded-2xl bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center text-2xl text-indigo-400 mx-auto mb-4 shadow-lg shadow-indigo-600/20">
          <i class="fa-solid fa-shield-halved"></i>
        </div>
        <h1 class="text-2xl font-black text-white tracking-wide">Control Panel</h1>
        <p class="text-xs text-slate-400 mt-1">Sign in to access server management</p>
      </div>

      <form id="loginForm" onsubmit="handleLogin(event)" class="space-y-4 relative">
        <div id="errorBox" class="hidden p-3 rounded-xl bg-red-950/50 border border-red-800/60 text-xs text-red-300 flex items-center gap-2">
          <i class="fa-solid fa-triangle-exclamation text-red-400"></i>
          <span id="errorMsg">Invalid username or password</span>
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-300 mb-1.5">Username</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <i class="fa-solid fa-user text-xs"></i>
            </span>
            <input type="text" id="username" required autocomplete="username" value="${currentAdminUser}" placeholder="${currentAdminUser}"
              class="w-full pl-10 pr-4 py-2.5 bg-slate-900/90 border border-slate-700/80 rounded-xl text-xs text-white placeholder-slate-500 focus:border-indigo-500 focus:outline-none transition-colors">
          </div>
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-300 mb-1.5">Password</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <i class="fa-solid fa-lock text-xs"></i>
            </span>
            <input type="password" id="password" required autocomplete="current-password" placeholder="••••••••"
              class="w-full pl-10 pr-4 py-2.5 bg-slate-900/90 border border-slate-700/80 rounded-xl text-xs text-white placeholder-slate-500 focus:border-indigo-500 focus:outline-none transition-colors">
          </div>
        </div>

        <button type="submit" id="submitBtn"
          class="w-full mt-2 py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold transition-all shadow-lg shadow-indigo-600/30 flex items-center justify-center gap-2">
          <span>Sign In</span>
          <i class="fa-solid fa-arrow-right text-xs"></i>
        </button>
      </form>
    </div>
  </div>

  <script>
    async function handleLogin(e) {
      e.preventDefault();
      const errBox = document.getElementById('errorBox');
      const errText = document.getElementById('errorMsg');
      const btn = document.getElementById('submitBtn');
      errBox.classList.add('hidden');
      btn.disabled = true;

      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value.trim();

      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (data.success) {
          try { localStorage.setItem('admin_token', data.token); } catch(e) {}
          window.location.href = '/admin';
        } else {
          errText.textContent = data.error || 'Invalid username or password';
          errBox.classList.remove('hidden');
        }
      } catch (err) {
        errText.textContent = 'Network error: ' + err.message;
        errBox.classList.remove('hidden');
      } finally {
        btn.disabled = false;
      }
    }
  </script>
</body>
</html>`;

  res.send(html);
});

// Admin Auth APIs
adminApp.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const adminCreds = getAdminCredentials();

  let isValid = false;
  if (username === adminCreds.username) {
    if (adminCreds.passwordHash) {
      try {
        isValid = bcrypt.compareSync(password, adminCreds.passwordHash);
      } catch (e) {
        isValid = false;
      }
    } else {
      isValid = (password === adminCreds.plainPassword);
    }
  }

  if (isValid) {
    const token = jwt.sign({ role: 'admin', user: adminCreds.username }, JWT_SECRET, { expiresIn: '90d' });
    res.setHeader('Set-Cookie', `admin_token=${token}; HttpOnly; Path=/; Max-Age=7776000; SameSite=Lax`);
    return res.json({ success: true, token });
  }
  return res.status(401).json({ success: false, error: 'Invalid username or password' });
});

adminApp.post('/api/admin/change-credentials', requireAdminAuth, (req, res) => {
  const { currentPassword, newUsername, newPassword } = req.body;
  if (!newUsername || !newUsername.trim()) {
    return res.status(400).json({ success: false, error: 'Username cannot be empty' });
  }
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ success: false, error: 'Password must be at least 4 characters' });
  }

  const adminCreds = getAdminCredentials();
  let isCurrentValid = false;
  if (adminCreds.passwordHash) {
    try {
      isCurrentValid = bcrypt.compareSync(currentPassword || '', adminCreds.passwordHash);
    } catch(e) {
      isCurrentValid = false;
    }
  } else {
    isCurrentValid = (currentPassword === adminCreds.plainPassword);
  }

  if (!isCurrentValid) {
    return res.status(400).json({ success: false, error: 'Current password is incorrect' });
  }

  const cleanUser = newUsername.trim();
  const newHash = bcrypt.hashSync(newPassword, 10);
  setSetting('admin_username', cleanUser);
  setSetting('admin_password_hash', newHash);
  setSetting('admin_password', ''); // clear plain

  const token = jwt.sign({ role: 'admin', user: cleanUser }, JWT_SECRET, { expiresIn: '90d' });
  res.setHeader('Set-Cookie', `admin_token=${token}; HttpOnly; Path=/; Max-Age=7776000; SameSite=Lax`);

  return res.json({ success: true, message: 'Credentials updated successfully' });
});

adminApp.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'admin_token=; HttpOnly; Path=/; Max-Age=0');
  res.json({ success: true });
});

// Admin Dashboard Route
adminApp.get('/admin', requireAdminAuth, async (req, res) => {
  const servers = db.prepare('SELECT * FROM servers').all();
  const dpUrlSetting = getSetting('discopanel_url', 'http://192.168.10.127:8080');
  let adminDpHost = '127.0.0.1';
  try { adminDpHost = new URL(dpUrlSetting).hostname; } catch(e) {}

  for (const s of servers) {
    const customHost = getSetting('public_server_host_' + s.id) || getSetting('public_server_host');
    const pInfo = await queryServerPing(s.port || 25565, adminDpHost, customHost || s.ip);
    if (pInfo && pInfo.success) {
      s.online = pInfo.online;
      s.max_online = pInfo.max;
      s.maxOnline = pInfo.max;
      try {
        db.prepare('UPDATE servers SET online = ?, max_online = ? WHERE id = ?').run(s.online, s.max_online, s.id);
      } catch(e) {}
    }
  }
  const users = db.prepare('SELECT id, username, uuid, skin_url, created_at FROM users ORDER BY id DESC').all();
  const dpUrl = getSetting('discopanel_url', 'http://192.168.10.127:8080');
  const dpToken = getSetting('discopanel_token', '');
  const launcherUrl = 'http://' + (req.hostname || '192.168.10.123') + ':' + LAUNCHER_PORT;
  const currentAdminUser = getAdminCredentials().username;

  servers.forEach(s => {
    s.maxOnline = s.max_online || 100;
    s.manifestUrl = s.manifest_url || `/api/servers/${s.id}/manifest`;
    const modsDir = path.join(SERVERS_DIR, s.id, 'mods');
    const allMods = fs.existsSync(modsDir) ? fs.readdirSync(modsDir).filter(f => f.endsWith('.jar')) : [];

    // Read client_mods.json
    const clientModsFile = path.join(SERVERS_DIR, s.id, 'client_mods.json');
    let clientMods = [];
    try {
      if (fs.existsSync(clientModsFile)) {
        clientMods = JSON.parse(fs.readFileSync(clientModsFile, 'utf8'));
      }
    } catch(e) {}
    const clientModsSet = new Set(clientMods);

    // Read disabled_mods.json
    const disabledModsFile = path.join(SERVERS_DIR, s.id, 'disabled_mods.json');
    let disabledMods = [];
    try {
      if (fs.existsSync(disabledModsFile)) {
        disabledMods = JSON.parse(fs.readFileSync(disabledModsFile, 'utf8'));
      }
    } catch(e) {}
    const disabledModsSet = new Set(disabledMods);

    // Read dp_mods.json (mods present on the Minecraft server via DiscoPanel)
    const dpModsFile = path.join(SERVERS_DIR, s.id, 'dp_mods.json');
    let dpMods = [];
    try {
      if (fs.existsSync(dpModsFile)) {
        dpMods = JSON.parse(fs.readFileSync(dpModsFile, 'utf8'));
      }
    } catch(e) {}
    const dpModsSet = new Set(dpMods);

    // If dp_mods.json not yet written, fallback to local jar files
    const serverModNames = dpMods.length > 0 ? dpMods : allMods;

    s.serverModsList = serverModNames.map(m => {
      let sizeMb = '0.0';
      try {
        const stat = fs.statSync(path.join(modsDir, m));
        sizeMb = (stat.size / (1024 * 1024)).toFixed(1);
      } catch (e) {}
      const isClient = clientModsSet.has(m);
      return {
        name: m,
        isClient,
        sizeMb
      };
    });

    s.clientModsList = allMods.filter(m => clientModsSet.has(m)).map(m => {
      let sizeMb = '0.0';
      try {
        const stat = fs.statSync(path.join(modsDir, m));
        sizeMb = (stat.size / (1024 * 1024)).toFixed(1);
      } catch (e) {}
      const isEnabled = !disabledModsSet.has(m);
      const isFromServer = dpModsSet.has(m);
      return {
        name: m,
        isClient: true,
        isEnabled,
        isFromServer,
        sizeMb
      };
    });

    s.totalMods = s.clientModsList.length;
    s.enabledModsCount = s.clientModsList.filter(m => m.isEnabled).length;
    s.disabledModsCount = s.clientModsList.length - s.enabledModsCount;
    s.isModsSyncEnabled = getSetting('sync_mods_' + s.id, 'true') !== 'false';
    const customHost = getSetting('public_server_host_' + s.id) || getSetting('public_server_host');
    if (customHost && customHost.trim()) {
      const parsed = parseHostAndPort(customHost, s.ip, s.port || 25565);
      s.ip = parsed.host;
      s.port = parsed.port;
    }
    s.publicHost = customHost || '';

    // Shaders list
    const shadersDir = path.join(SERVERS_DIR, s.id, 'shaderpacks');
    if (!fs.existsSync(shadersDir)) fs.mkdirSync(shadersDir, { recursive: true });
    s.shadersList = fs.readdirSync(shadersDir).filter(f => f.endsWith('.zip')).map(f => {
      let sizeMb = '0.0';
      try {
        const stat = fs.statSync(path.join(shadersDir, f));
        sizeMb = (stat.size / (1024 * 1024)).toFixed(1);
      } catch (e) {}
      return { name: f, sizeMb };
    });

    // Resource packs list
    const rpDir = path.join(SERVERS_DIR, s.id, 'resourcepacks');
    if (!fs.existsSync(rpDir)) fs.mkdirSync(rpDir, { recursive: true });
    s.resourcepacksList = fs.readdirSync(rpDir).filter(f => f.endsWith('.zip')).map(f => {
      let sizeMb = '0.0';
      try {
        const stat = fs.statSync(path.join(rpDir, f));
        sizeMb = (stat.size / (1024 * 1024)).toFixed(1);
      } catch (e) {}
      return { name: f, sizeMb };
    });
  });

  const totalRunning = servers.filter(s => s.status === 'online').length;
  const totalStopped = servers.length - totalRunning;
  const totalPlayersOnline = servers.reduce((acc, s) => acc + (s.online || 0), 0);
  const totalModsCount = servers.reduce((acc, s) => acc + (s.totalMods || 0), 0);
  const totalShadersCount = servers.reduce((acc, s) => acc + (s.shadersList?.length || 0), 0);
  const totalPacksCount = servers.reduce((acc, s) => acc + (s.resourcepacksList?.length || 0), 0);
  const adminInitials = (currentAdminUser || 'AD').substring(0, 2).toUpperCase();

  const html = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DiscoPanel - Servers & Modpacks</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    body {
      background-color: #0c0d12;
      color: #e2e8f0;
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
    }
    font-mono { font-family: 'JetBrains Mono', monospace; }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #08090d; }
    ::-webkit-scrollbar-thumb { background: #1e2230; border-radius: 9999px; }
    ::-webkit-scrollbar-thumb:hover { background: #2e354a; }
  </style>
</head>
<body class="h-screen flex overflow-hidden bg-[#0c0d12] text-slate-200">

  <!-- ================= SIDEBAR ================= -->
  <aside class="w-64 bg-[#08090d] border-r border-[#161822] flex flex-col justify-between shrink-0 select-none">
    <div class="p-4 flex flex-col h-full overflow-y-auto">
      
      <!-- Brand Header -->
      <div class="flex items-center gap-3 px-2 py-3 mb-6">
        <div class="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 text-lg shadow-lg shadow-emerald-500/10">
          <i class="fa-solid fa-cubes-stacked"></i>
        </div>
        <div>
          <div class="flex items-center gap-1.5">
            <span class="font-black text-white text-base tracking-tight">DiscoPanel</span>
            <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          </div>
          <span class="text-[10px] text-slate-500 font-mono">Launcher & Server Sync</span>
        </div>
      </div>

      <!-- Navigation Section -->
      <div class="space-y-1 mb-6">
        <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider px-3 mb-2">Navigation</div>
        
        <button onclick="switchNav('dashboard')" id="nav_dashboard" class="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-[#12141c] transition-all">
          <div class="flex items-center gap-3">
            <i class="fa-solid fa-chart-pie w-4 text-center text-slate-400"></i>
            <span>Dashboard</span>
          </div>
        </button>

        <button onclick="switchNav('servers')" id="nav_servers" class="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-bold text-white bg-[#151824] border border-[#222738] shadow-sm transition-all">
          <div class="flex items-center gap-3">
            <i class="fa-solid fa-server w-4 text-center text-emerald-400"></i>
            <span>Servers</span>
          </div>
          <span class="px-2 py-0.5 rounded-md bg-[#1f2438] text-[10px] font-mono text-slate-300 font-bold">${servers.length}</span>
        </button>

        <button onclick="switchNav('files')" id="nav_files" class="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-[#12141c] transition-all">
          <div class="flex items-center gap-3">
            <i class="fa-solid fa-folder-tree w-4 text-center text-amber-400"></i>
            <span>Файловый менеджер</span>
          </div>
          <span class="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 text-[9px] font-mono font-bold">FS</span>
        </button>

        <button onclick="switchNav('settings')" id="nav_settings" class="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-[#12141c] transition-all">
          <div class="flex items-center gap-3">
            <i class="fa-solid fa-gear w-4 text-center text-slate-400"></i>
            <span>Settings</span>
          </div>
        </button>

        <button onclick="switchNav('api')" id="nav_api" class="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-[#12141c] transition-all">
          <div class="flex items-center gap-3">
            <i class="fa-solid fa-satellite-dish w-4 text-center text-slate-400"></i>
            <span>API Launcher</span>
          </div>
          <span class="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 text-[9px] font-mono font-bold">:6500</span>
        </button>
      </div>

      <!-- Quick Access Section -->
      <div class="space-y-1 flex-1">
        <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider px-3 mb-2">Quick Access</div>
        ${servers.map(s => `
          <button onclick="scrollToServer('${s.id}')" class="w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white hover:bg-[#12141c] transition-all truncate">
            <span class="w-2 h-2 rounded-full ${s.status === 'online' ? 'bg-emerald-400' : 'bg-red-400'} shrink-0"></span>
            <span class="truncate text-left">${s.name}</span>
          </button>
        `).join('')}
      </div>

      <!-- User Profile Box -->
      <div class="pt-4 border-t border-[#161822] mt-4">
        <div class="p-2.5 rounded-xl bg-[#0f1118] border border-[#1b1e2a] flex items-center justify-between gap-3">
          <div class="flex items-center gap-2.5 min-w-0">
            <div class="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-xs text-white shrink-0">
              ${adminInitials}
            </div>
            <div class="min-w-0">
              <div class="text-xs font-bold text-white truncate">${currentAdminUser}</div>
              <div class="text-[10px] text-slate-500">Administrator</div>
            </div>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <button onclick="openCredentialsModal()" title="Change Username & Password" class="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors">
              <i class="fa-solid fa-key text-xs"></i>
            </button>
            <button onclick="logoutAdmin()" title="Log Out" class="p-1.5 rounded-lg hover:bg-red-950/40 text-slate-400 hover:text-red-400 transition-colors">
              <i class="fa-solid fa-right-from-bracket text-xs"></i>
            </button>
          </div>
        </div>

        <div class="flex items-center justify-between px-2 pt-3 text-[10px] text-slate-600 font-mono">
          <span>v1.2.5</span>
          <span class="flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> Online</span>
        </div>
      </div>

    </div>
  </aside>

  <!-- ================= MAIN CONTENT ================= -->
  <main class="flex-1 flex flex-col overflow-y-auto bg-[#0c0d12]">

    <!-- ================= SECTION: SERVERS ================= -->
    <div id="section_servers" class="p-8 max-w-6xl w-full mx-auto space-y-6">
      
      <!-- Top Title Bar -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#161822]">
        <div class="flex items-center gap-3.5">
          <div class="w-11 h-11 rounded-2xl bg-[#141620] border border-[#202434] flex items-center justify-center text-slate-200 text-lg shadow-sm">
            <i class="fa-solid fa-server"></i>
          </div>
          <div>
            <h1 class="text-xl font-black text-white tracking-tight">Servers</h1>
            <p class="text-xs text-slate-400">Click a server to manage mods, shaders, and configurations</p>
          </div>
        </div>
      </div>

      <!-- Search & Status Bar -->
      <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
        <div class="relative flex-1 max-w-md">
          <i class="fa-solid fa-magnifying-glass absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 text-xs"></i>
          <input type="text" id="serverSearchInput" oninput="filterServers(this.value)" placeholder="Search by name, version, or mod loader..." class="w-full bg-[#11131a] border border-[#1d202c] rounded-xl pl-9 pr-4 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500/60 font-sans transition-all">
        </div>

        <div class="flex items-center gap-4 text-xs font-semibold text-slate-400 px-2">
          <div class="flex items-center gap-1.5">
            <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>${totalRunning} running</span>
          </div>
          <div class="flex items-center gap-1.5">
            <span class="w-2 h-2 rounded-full bg-slate-600"></span>
            <span>${totalStopped} stopped</span>
          </div>
        </div>
      </div>

      <!-- Server Cards List -->
      <div id="serversContainer" class="space-y-4">
        ${servers.map(s => `
          <div id="serverCard_${s.id}" data-search="${(s.name + ' ' + s.version + ' ' + s.modloader + ' ' + (s.description||'')).toLowerCase()}" class="bg-[#11131a] border border-[#1b1e2a] hover:border-[#2a2f44] rounded-2xl p-5 transition-all space-y-4">
            
            <!-- Clickable Server Header (Clicking anywhere opens details) -->
            <div onclick="toggleServerDetails('${s.id}')" class="flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer select-none group">
              <div class="flex items-start sm:items-center gap-3.5">
                <div class="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/30 group-hover:border-blue-500/60 flex items-center justify-center text-blue-400 text-base shrink-0 shadow-sm transition-all">
                  <i class="fa-solid fa-cube"></i>
                </div>
                <div>
                  <div class="flex items-center gap-2">
                    <h3 class="text-base font-bold text-white group-hover:text-blue-300 tracking-tight transition-colors">${s.name}</h3>
                  </div>
                  <p class="text-xs text-slate-400 mt-0.5">${s.description || 'Minecraft server'}</p>
                </div>
              </div>

              <!-- Badges & Arrow -->
              <div class="flex flex-wrap items-center gap-2">
                <div class="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold">
                  <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                  <span>Running</span>
                </div>
                <span class="px-2.5 py-1 rounded-lg bg-[#181b26] border border-[#222738] text-slate-300 text-xs font-mono font-medium">${s.version}</span>
                <span class="px-2.5 py-1 rounded-lg bg-[#181b26] border border-[#222738] text-slate-300 text-xs font-mono font-medium capitalize">${s.modloader}</span>

                <div class="ml-2 px-3 py-1 rounded-lg bg-[#161822] group-hover:bg-[#202434] border border-[#232738] text-xs font-semibold text-slate-300 flex items-center gap-1.5 transition-all">
                  <span>Mods & Files</span>
                  <i id="toggleArrow_${s.id}" class="fa-solid fa-chevron-down text-[10px] ml-1 transition-transform"></i>
                </div>
              </div>
            </div>

            <!-- 4 Metric Widgets (Exact like DiscoPanel) -->
            <div onclick="toggleServerDetails('${s.id}')" class="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1 cursor-pointer">
              <div class="p-3 rounded-xl bg-[#0b0c11] border border-[#171924] hover:border-slate-700 transition-colors">
                <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
                  <i class="fa-solid fa-network-wired text-slate-400"></i> PORT
                </div>
                <div class="text-sm font-bold text-white font-mono mt-1">${s.port}</div>
              </div>

              <div class="p-3 rounded-xl bg-[#0b0c11] border border-[#171924] hover:border-slate-700 transition-colors">
                <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
                  <i class="fa-solid fa-puzzle-piece text-cyan-400"></i> MODS
                </div>
                <div class="text-sm font-bold font-mono mt-1">
                  <span class="text-cyan-400 font-bold">${s.enabledModsCount}</span> <span class="text-slate-500 text-xs">/ ${s.totalMods} enabled</span>
                </div>
              </div>

              <div class="p-3 rounded-xl bg-[#0b0c11] border border-[#171924] hover:border-slate-700 transition-colors">
                <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
                  <i class="fa-solid fa-users text-emerald-400"></i> PLAYERS
                </div>
                <div class="text-sm font-bold font-mono mt-1">
                  <span id="serverOnline_${s.id}" class="text-emerald-400 font-bold">${s.online || 0}</span> <span class="text-slate-500">/ <span id="serverMaxOnline_${s.id}">${s.maxOnline}</span></span>
                </div>
              </div>

              <div class="p-3 rounded-xl bg-[#0b0c11] border border-[#171924] hover:border-slate-700 transition-colors">
                <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
                  <i class="fa-solid fa-bolt text-emerald-400"></i> STATUS
                </div>
                <div class="text-sm font-bold text-emerald-400 font-mono mt-1">Online</div>
              </div>
            </div>

            <!-- Expandable Management Section -->
            <div id="details_${s.id}" class="hidden pt-4 border-t border-[#1a1d2b] space-y-6">
              
              <!-- Tabs inside Server Details -->
              <div class="flex items-center gap-2 border-b border-[#1f2232] pb-2">
                <button onclick="switchServerTab('${s.id}', 'mods')" id="srvTabBtn_${s.id}_mods" class="px-4 py-1.5 rounded-lg text-xs font-bold flex items-center gap-2 bg-indigo-600 text-white shadow-sm transition-all">
                  <i class="fa-solid fa-puzzle-piece"></i>
                  <span>Mods</span>
                  <span class="px-1.5 py-0.2 rounded bg-indigo-500/40 text-[10px] font-mono">${s.totalMods}</span>
                </button>
                <button onclick="switchServerTab('${s.id}', 'shaders')" id="srvTabBtn_${s.id}_shaders" class="px-4 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white bg-[#12141c] hover:bg-[#1a1d28] transition-all flex items-center gap-1.5">
                  <i class="fa-solid fa-sun text-amber-400"></i>
                  <span>Shaders</span>
                  <span class="text-[10px] text-slate-500 font-mono">${s.shadersList.length}</span>
                </button>
                <button onclick="switchServerTab('${s.id}', 'resourcepacks')" id="srvTabBtn_${s.id}_resourcepacks" class="px-4 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white bg-[#12141c] hover:bg-[#1a1d28] transition-all flex items-center gap-1.5">
                  <i class="fa-solid fa-palette text-emerald-400"></i>
                  <span>Resourcepacks</span>
                  <span class="text-[10px] text-slate-500 font-mono">${s.resourcepacksList.length}</span>
                </button>
                <button onclick="switchServerTab('${s.id}', 'host')" id="srvTabBtn_${s.id}_host" class="px-4 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white bg-[#12141c] hover:bg-[#1a1d28] transition-all flex items-center gap-1.5">
                  <i class="fa-solid fa-globe text-cyan-400"></i>
                  <span>Server Address</span>
                </button>
              </div>

              <!-- ================= TAB: MODS ================= -->
              <div id="srvTab_${s.id}_mods" class="space-y-4">
                
                <!-- Mods Controls Bar -->
                <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-[#0b0c11] border border-[#1a1d2b] p-3.5 rounded-xl">
                  <div class="flex items-center gap-2 flex-wrap">
                    <!-- Sub-tabs: Client mods vs DiscoPanel server mods -->
                    <button type="button" onclick="switchModSubTab('${s.id}', 'client')" id="modSubBtn_${s.id}_client" class="px-3 py-1.5 rounded-lg text-xs font-bold bg-indigo-600 text-white shadow-sm transition-all flex items-center gap-1.5">
                      <i class="fa-solid fa-laptop text-xs"></i>
                      <span>Клиентские моды</span>
                      <span class="text-[10px] px-1.5 py-0.2 rounded bg-indigo-900/60 font-mono">${s.clientModsList.length}</span>
                    </button>
                    <button type="button" onclick="switchModSubTab('${s.id}', 'server')" id="modSubBtn_${s.id}_server" class="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white bg-[#12141c] hover:bg-[#1a1d28] transition-all flex items-center gap-1.5">
                      <i class="fa-solid fa-server text-xs text-purple-400"></i>
                      <span>Моды с DiscoPanel</span>
                      <span class="text-[10px] px-1.5 py-0.2 rounded bg-purple-950/80 text-purple-300 font-mono">${s.serverModsList.length}</span>
                    </button>
                    <!-- Quick Mod Search -->
                    <div class="relative w-full sm:w-48 ml-0 sm:ml-2">
                      <i class="fa-solid fa-magnifying-glass absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-xs"></i>
                      <input type="text" oninput="filterModRows('${s.id}', this.value)" placeholder="Поиск модов..." class="w-full bg-[#12141c] border border-slate-700/80 rounded-lg pl-8 pr-3 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500 font-sans">
                    </div>
                  </div>

                  <!-- Upload Mod Button -->
                  <div>
                    <input type="file" id="modFile_${s.id}" multiple accept=".jar" class="hidden" onchange="uploadClientMods('${s.id}', this.files)">
                    <button onclick="document.getElementById('modFile_${s.id}').click()" class="w-full sm:w-auto px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold flex items-center justify-center gap-2 transition-all shadow-md">
                      <i class="fa-solid fa-plus text-xs"></i>
                      <span>Загрузить клиентский .jar</span>
                    </button>
                  </div>
                </div>

                <!-- SUB-PANE 1: CLIENT MODS -->
                <div id="modSubPane_${s.id}_client" class="space-y-3">
                  ${s.clientModsList.length === 0 ? `
                    <div class="p-8 text-center bg-[#0b0c11] border border-dashed border-[#1a1d2b] rounded-xl text-xs text-slate-500">
                      Нет активных клиентских модов. Загрузите .jar файл вручную или перейдите во вкладку «Моды с DiscoPanel» для импорта модов с сервера.
                    </div>
                  ` : `
                    <div class="bg-[#0b0c11] border border-[#1a1d2b] rounded-xl overflow-hidden">
                      <div class="max-h-[380px] overflow-y-auto divide-y divide-[#151724]">
                        ${s.clientModsList.map(m => `
                          <div id="modRow_${s.id}_${encodeURIComponent(m.name)}" data-name="${m.name.toLowerCase()}" class="flex items-center justify-between p-3 hover:bg-[#121520] transition-colors gap-3">
                            <!-- Switch + Name -->
                            <div class="flex items-center gap-3 min-w-0">
                              <label class="relative inline-flex items-center cursor-pointer shrink-0">
                                <input type="checkbox" ${m.isEnabled ? 'checked' : ''} onchange="toggleMod('${s.id}', '${m.name}', this.checked)" class="sr-only peer">
                                <div class="w-8 h-4 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-3 after:w-3.5 after:transition-all peer-checked:bg-emerald-500"></div>
                              </label>

                              <div class="min-w-0">
                                <div class="text-xs font-medium font-mono text-slate-200 truncate ${!m.isEnabled ? 'line-through text-slate-500' : ''}" id="modTitle_${s.id}_${encodeURIComponent(m.name)}">
                                  ${m.name}
                                </div>
                                <div class="text-[10px] text-slate-500 font-sans mt-0.5">
                                  ${m.sizeMb} MB &bull; ${m.isEnabled ? '<span class="text-emerald-400 font-semibold">Включен (скачивается игрокам)</span>' : '<span class="text-slate-500">Отключен</span>'}
                                </div>
                              </div>
                            </div>

                            <!-- Badges & Delete -->
                            <div class="flex items-center gap-2 shrink-0">
                              <span class="px-2 py-0.5 rounded text-[10px] font-semibold ${m.isFromServer ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20' : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'}">
                                ${m.isFromServer ? 'DiscoPanel + Client' : 'Client-only'}
                              </span>
                              <button onclick="deleteMod('${s.id}', '${m.name}')" title="Удалить из клиентских модов" class="p-1.5 rounded hover:bg-red-950/40 text-slate-500 hover:text-red-400 transition-colors">
                                <i class="fa-solid fa-trash-can text-xs"></i>
                              </button>
                            </div>
                          </div>
                        `).join('')}
                      </div>
                    </div>
                  `}
                </div>

                <!-- SUB-PANE 2: DISCOPANEL SERVER MODS -->
                <div id="modSubPane_${s.id}_server" class="hidden space-y-3">
                  <div class="p-3 rounded-xl bg-purple-950/20 border border-purple-800/30 text-xs text-purple-200 flex items-start gap-2.5">
                    <i class="fa-solid fa-circle-info text-purple-400 mt-0.5 shrink-0"></i>
                    <div>
                      <div class="font-bold text-white text-xs">Моды игрового сервера (DiscoPanel) &bull; Установлено на сервере: ${s.serverModsList.length}</div>
                      <div class="text-[11px] text-slate-400 mt-0.5">
                        Здесь отображаются все моды, установленные на сервере Minecraft.
                        Моды со статусом <span class="text-emerald-400 font-semibold">«Добавлен клиентам»</span> автоматически скачиваются игрокам в лаунчер.
                        Моды со статусом <span class="text-purple-400 font-semibold">«Только сервер»</span> игрокам не передаются — нажмите <span class="text-indigo-300 font-semibold">«Импортировать для игроков»</span>, чтобы добавить мод в лаунчер.
                      </div>
                    </div>
                  </div>

                  ${s.serverModsList.length === 0 ? `
                    <div class="p-8 text-center bg-[#0b0c11] border border-dashed border-[#1a1d2b] rounded-xl text-xs text-slate-500">
                      Моды сервера ещё не синхронизированы с DiscoPanel. Нажмите «Синхронизировать сейчас» в настройках API.
                    </div>
                  ` : `
                    <div class="bg-[#0b0c11] border border-[#1a1d2b] rounded-xl overflow-hidden">
                      <div class="max-h-[380px] overflow-y-auto divide-y divide-[#151724]">
                        ${s.serverModsList.map(m => `
                          <div id="modRow_${s.id}_${encodeURIComponent(m.name)}" data-name="${m.name.toLowerCase()}" class="flex items-center justify-between p-3 hover:bg-[#121520] transition-colors gap-3">
                            <div class="flex items-center gap-3 min-w-0">
                              <i class="fa-solid fa-server ${m.isClient ? 'text-emerald-400' : 'text-purple-400'} text-xs shrink-0"></i>
                              <div class="min-w-0">
                                <div class="text-xs font-medium font-mono text-slate-200 truncate">
                                  ${m.name}
                                </div>
                                <div class="text-[10px] text-slate-500 font-sans mt-0.5">
                                  ${m.sizeMb} MB &bull; ${m.isClient ? '<span class="text-emerald-400 font-semibold"><i class="fa-solid fa-check"></i> Импортирован для игроков (скачивается в лаунчер)</span>' : '<span class="text-purple-400 font-semibold">Только сервер (DiscoPanel)</span>'}
                                </div>
                              </div>
                            </div>

                            <div class="flex items-center gap-2 shrink-0">
                              ${m.isClient ? `
                                <span class="px-2.5 py-1 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-semibold flex items-center gap-1.5">
                                  <i class="fa-solid fa-check text-xs"></i>
                                  <span>Добавлен клиентам</span>
                                </span>
                                <button type="button" onclick="unimportDpMod('${s.id}', '${m.name}')" title="Убрать из модов для игроков" class="p-1.5 rounded hover:bg-red-950/40 text-slate-500 hover:text-red-400 transition-colors">
                                  <i class="fa-solid fa-xmark text-xs"></i>
                                </button>
                              ` : `
                                <button type="button" onclick="importDpMod('${s.id}', '${m.name}')" class="px-3 py-1.5 rounded-lg bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-200 border border-indigo-500/40 text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm">
                                  <i class="fa-solid fa-plus text-xs"></i>
                                  <span>Импортировать для игроков</span>
                                </button>
                              `}
                            </div>
                          </div>
                        `).join('')}
                      </div>
                    </div>
                  `}
                </div>

              </div>

              <!-- ================= TAB: SHADERS ================= -->
              <div id="srvTab_${s.id}_shaders" class="hidden space-y-4">
                <div class="flex items-center justify-between bg-[#0b0c11] border border-[#1a1d2b] p-3.5 rounded-xl">
                  <div>
                    <div class="text-xs font-bold text-amber-400 flex items-center gap-2">
                      <i class="fa-solid fa-sun"></i>
                      <span>Shaders (shaderpacks)</span>
                    </div>
                    <p class="text-[11px] text-slate-400 mt-0.5">.zip archives for Oculus/Iris/OptiFine, automatically downloaded to players</p>
                  </div>
                  <div>
                    <input type="file" id="shaderFile_${s.id}" multiple accept=".zip" class="hidden" onchange="uploadShaders('${s.id}', this.files)">
                    <button onclick="document.getElementById('shaderFile_${s.id}').click()" class="px-4 py-1.5 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 border border-amber-500/30 text-amber-300 text-xs font-bold flex items-center gap-2 transition-all">
                      <i class="fa-solid fa-plus text-xs"></i>
                      <span>Upload .zip</span>
                    </button>
                  </div>
                </div>

                ${s.shadersList.length === 0 ? `
                  <div class="p-6 text-center bg-[#0b0c11] border border-dashed border-[#1a1d2b] rounded-xl text-xs text-slate-500">
                    No shaders uploaded yet. Click "Upload .zip" above.
                  </div>
                ` : `
                  <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                    ${s.shadersList.map(sh => `
                      <div class="flex items-center justify-between p-3 rounded-xl bg-[#0b0c11] border border-[#1a1d2b]">
                        <div class="flex items-center gap-2 min-w-0">
                          <i class="fa-solid fa-sun text-amber-400 text-xs"></i>
                          <div class="truncate text-xs font-mono text-slate-200">${sh.name}</div>
                        </div>
                        <div class="flex items-center gap-2 shrink-0">
                          <span class="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 font-sans">${sh.sizeMb}MB</span>
                          <button onclick="deleteShader('${s.id}', '${sh.name}')" title="Delete" class="text-slate-500 hover:text-red-400 transition-colors p-1">
                            <i class="fa-solid fa-trash-can text-xs"></i>
                          </button>
                        </div>
                      </div>
                    `).join('')}
                  </div>
                `}
              </div>

              <!-- ================= TAB: RESOURCEPACKS ================= -->
              <div id="srvTab_${s.id}_resourcepacks" class="hidden space-y-4">
                <div class="flex items-center justify-between bg-[#0b0c11] border border-[#1a1d2b] p-3.5 rounded-xl">
                  <div>
                    <div class="text-xs font-bold text-emerald-400 flex items-center gap-2">
                      <i class="fa-solid fa-palette"></i>
                      <span>Resourcepacks (resourcepacks)</span>
                    </div>
                    <p class="text-[11px] text-slate-400 mt-0.5">.zip texture and audio archives, automatically downloaded to player game folder</p>
                  </div>
                  <div>
                    <input type="file" id="rpFile_${s.id}" multiple accept=".zip" class="hidden" onchange="uploadResourcepacks('${s.id}', this.files)">
                    <button onclick="document.getElementById('rpFile_${s.id}').click()" class="px-4 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-300 text-xs font-bold flex items-center gap-2 transition-all">
                      <i class="fa-solid fa-plus text-xs"></i>
                      <span>Upload .zip</span>
                    </button>
                  </div>
                </div>

                ${s.resourcepacksList.length === 0 ? `
                  <div class="p-6 text-center bg-[#0b0c11] border border-dashed border-[#1a1d2b] rounded-xl text-xs text-slate-500">
                    No resource packs uploaded yet. Click "Upload .zip" above.
                  </div>
                ` : `
                  <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                    ${s.resourcepacksList.map(rp => `
                      <div class="flex items-center justify-between p-3 rounded-xl bg-[#0b0c11] border border-[#1a1d2b]">
                        <div class="flex items-center gap-2 min-w-0">
                          <i class="fa-solid fa-palette text-emerald-400 text-xs"></i>
                          <div class="truncate text-xs font-mono text-slate-200">${rp.name}</div>
                        </div>
                        <div class="flex items-center gap-2 shrink-0">
                          <span class="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 font-sans">${rp.sizeMb}MB</span>
                          <button onclick="deleteResourcepack('${s.id}', '${rp.name}')" title="Delete" class="text-slate-500 hover:text-red-400 transition-colors p-1">
                            <i class="fa-solid fa-trash-can text-xs"></i>
                          </button>
                        </div>
                      </div>
                    `).join('')}
                  </div>
                `}
              </div>

              <!-- ================= TAB: HOST ================= -->
              <div id="srvTab_${s.id}_host" class="hidden space-y-4">
                <div class="p-4 rounded-xl bg-[#0b0c11] border border-[#1a1d2b] space-y-3">
                  <div>
                    <span class="text-xs font-bold text-white flex items-center gap-1.5">
                      <i class="fa-solid fa-globe text-cyan-400"></i>
                      Публичный адрес сервера (домен или IP с портом)
                    </span>
                    <p class="text-[11px] text-slate-400 mt-0.5">Игроки в лаунчере подключаются по адресу: <code class="text-cyan-300 font-mono font-bold">${s.ip}:${s.port}</code></p>
                  </div>
                  <div class="flex items-center gap-2 max-w-lg">
                    <input type="text" id="hostInput_${s.id}" value="${s.publicHost || ''}" placeholder="например: mc.varrimain.site или 95.78.23.54:25565" class="flex-1 bg-[#12141c] border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-cyan-300 font-mono focus:border-indigo-500 focus:outline-none">
                    <button onclick="savePublicHost('${s.id}')" class="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-bold text-white transition-all shrink-0">
                      Сохранить
                    </button>
                  </div>
                  <p class="text-[11px] text-slate-500">
                    Введите домен или IP целиком (например, <code class="text-slate-400">mc.varrimain.site</code> или <code class="text-slate-400">mc.varrimain.site:25565</code>). Если порт не указан, по умолчанию используется стандартный порт Minecraft <b>25565</b>.
                  </p>
                </div>
              </div>

            </div>

          </div>
        `).join('')}
      </div>

    </div>

    <!-- ================= SECTION: SETTINGS ================= -->
    <div id="section_settings" class="hidden p-8 max-w-5xl w-full mx-auto space-y-6">
      <div class="pb-4 border-b border-[#161822]">
        <h1 class="text-xl font-black text-white tracking-tight">Settings</h1>
        <p class="text-xs text-slate-400">Launcher API configuration and DiscoPanel integration</p>
      </div>

      <!-- Launcher API Connection Card -->
      <div class="bg-[#11131a] border border-[#1b1e2a] rounded-2xl p-6 space-y-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 text-lg shrink-0">
            <i class="fa-solid fa-satellite-dish"></i>
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h2 class="text-sm font-bold text-white">Launcher API Address</h2>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">Port ${LAUNCHER_PORT}</span>
            </div>
            <p class="text-xs text-slate-400 mt-0.5">Specify this URL in the launcher: Settings → Server Address</p>
          </div>
        </div>

        <div class="flex items-center gap-3 pt-2">
          <div class="flex-1 bg-[#0b0c11] border border-slate-700/60 rounded-xl px-4 py-2.5 font-mono text-sm text-cyan-300 select-all">
            <span id="launcherApiUrl">${launcherUrl}</span>
          </div>
          <button onclick="copyLauncherUrl()" id="copyBtn" class="px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center gap-2 transition-all shadow-md shrink-0">
            <i class="fa-solid fa-copy"></i>
            <span id="copyBtnText">Copy</span>
          </button>
        </div>
      </div>

      <!-- DiscoPanel API Settings Box -->
      <div class="bg-[#11131a] border border-[#1b1e2a] rounded-2xl p-6 space-y-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400 text-lg shrink-0">
            <i class="fa-solid fa-link"></i>
          </div>
          <div>
            <h2 class="text-sm font-bold text-white">DiscoPanel API Integration</h2>
            <p class="text-xs text-slate-400 mt-0.5">Automatic server discovery and mod synchronization</p>
          </div>
        </div>

        <form id="apiConfigForm" onsubmit="saveApiConfig(event)" class="grid grid-cols-1 md:grid-cols-12 gap-3 pt-2">
          <div class="md:col-span-5">
            <label class="text-[11px] font-semibold text-slate-400 block mb-1">DiscoPanel URL</label>
            <input type="text" id="dpUrlInput" value="${dpUrl}" class="w-full bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3.5 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none font-mono">
          </div>
          <div class="md:col-span-5">
            <label class="text-[11px] font-semibold text-slate-400 block mb-1">API Token (with dp_ prefix)</label>
            <input type="password" id="dpTokenInput" value="${dpToken}" placeholder="dp_..." class="w-full bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3.5 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none font-mono">
          </div>
          <div class="md:col-span-2 flex items-end">
            <button type="submit" class="w-full py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-bold text-slate-200 transition-all">
              Save Settings
            </button>
          </div>
        </form>
      </div>

    </div>

    <!-- ================= SECTION: DASHBOARD ================= -->
    <div id="section_dashboard" class="hidden p-8 max-w-5xl w-full mx-auto space-y-6">
      <div class="pb-4 border-b border-[#161822]">
        <h1 class="text-xl font-black text-white tracking-tight">Dashboard</h1>
        <p class="text-xs text-slate-400">Overview statistics and server status</p>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div class="p-5 rounded-2xl bg-[#11131a] border border-[#1b1e2a]">
          <div class="text-xs font-bold text-slate-400 uppercase tracking-wider">Total Servers</div>
          <div class="text-3xl font-black text-white font-mono mt-2">${servers.length}</div>
          <div class="text-[11px] text-emerald-400 mt-1 flex items-center gap-1.5">
            <span class="w-2 h-2 rounded-full bg-emerald-400"></span> ${totalRunning} online
          </div>
        </div>

        <div class="p-5 rounded-2xl bg-[#11131a] border border-[#1b1e2a]">
          <div class="text-xs font-bold text-slate-400 uppercase tracking-wider">Online Players</div>
          <div id="dashTotalPlayersOnline" class="text-3xl font-black text-emerald-400 font-mono mt-2">${totalPlayersOnline}</div>
          <div class="text-[11px] text-slate-400 mt-1">across all servers</div>
        </div>

        <div class="p-5 rounded-2xl bg-[#11131a] border border-[#1b1e2a]">
          <div class="text-xs font-bold text-slate-400 uppercase tracking-wider">Mods & Packs</div>
          <div class="text-3xl font-black text-cyan-400 font-mono mt-2">${totalModsCount}</div>
          <div class="text-[11px] text-slate-400 mt-1">${totalShadersCount} shaders, ${totalPacksCount} resource packs</div>
        </div>
      </div>
    </div>

    <!-- ================= SECTION: API ================= -->
    <div id="section_api" class="hidden p-8 max-w-5xl w-full mx-auto space-y-6">
      <div class="pb-4 border-b border-[#161822]">
        <h1 class="text-xl font-black text-white tracking-tight">API Launcher Endpoints</h1>
        <p class="text-xs text-slate-400">Documentation and available endpoints for the launcher</p>
      </div>

      <div class="space-y-3">
        <div class="p-4 rounded-xl bg-[#11131a] border border-[#1b1e2a] font-mono text-xs">
          <div class="text-emerald-400 font-bold">GET /api/servers</div>
          <div class="text-slate-400 mt-1 text-[11px]">List of all servers displayed in the launcher</div>
        </div>
        <div class="p-4 rounded-xl bg-[#11131a] border border-[#1b1e2a] font-mono text-xs">
          <div class="text-emerald-400 font-bold">GET /api/servers/:id/manifest</div>
          <div class="text-slate-400 mt-1 text-[11px]">Synchronization manifest for files, mods, shaders, and resource packs</div>
        </div>
        <div class="p-4 rounded-xl bg-[#11131a] border border-[#1b1e2a] font-mono text-xs">
          <div class="text-emerald-400 font-bold">GET /files/:id/*</div>
          <div class="text-slate-400 mt-1 text-[11px]">Direct file download route for the launcher</div>
        </div>
      </div>
    </div>

    <!-- ================= SECTION: FILE MANAGER ================= -->
    <div id="section_files" class="hidden p-8 max-w-6xl w-full mx-auto space-y-6">
      
      <!-- FM Header -->
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#161822]">
        <div>
          <div class="flex items-center gap-2.5">
            <div class="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
              <i class="fa-solid fa-folder-tree"></i>
            </div>
            <h1 class="text-xl font-black text-white tracking-tight">Файловый менеджер серверов</h1>
          </div>
          <p class="text-xs text-slate-400 mt-1">Просмотр файлов серверов, доступ к архивным сборкам на диске и перенос ресурсов в один клик</p>
        </div>
        <div class="flex items-center gap-2">
          <button onclick="loadFmDirectory(fmCurrentPath)" class="px-3 py-1.5 rounded-xl bg-[#151824] hover:bg-[#1f2438] border border-[#222738] text-xs font-semibold text-slate-300 transition-all flex items-center gap-2 shadow-sm">
            <i class="fa-solid fa-rotate text-slate-400"></i>
            <span>Обновить</span>
          </button>
        </div>
      </div>

      <!-- Server Selector & Server Overview Card -->
      <div class="p-5 rounded-2xl bg-[#11131a] border border-[#1b1e2a] shadow-xl space-y-4">
        <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div class="space-y-1 flex-1">
            <label class="text-[11px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <i class="fa-solid fa-server text-indigo-400"></i>
              <span>Выберите сервер для работы с файлами</span>
            </label>
            <div class="flex flex-wrap items-center gap-3">
              <select id="fmServerSelect" onchange="onFmServerChange()" class="bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3 py-2 text-xs font-medium text-slate-200 focus:border-amber-500 focus:outline-none min-w-[280px]">
                <option value="">Загрузка списка серверов...</option>
              </select>
              <div id="fmServerBadge" class="hidden"></div>
            </div>
          </div>

          <!-- Server Level Quick Stats & Actions -->
          <div class="flex flex-wrap items-center gap-2">
            <div id="fmServerStats" class="flex items-center gap-2 text-xs text-slate-400"></div>
            <button id="fmMigrateBtn" onclick="openMigrateModal()" class="hidden px-3.5 py-2 rounded-xl bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-xs font-bold text-white shadow-lg shadow-amber-900/30 transition-all flex items-center gap-2">
              <i class="fa-solid fa-bolt"></i>
              <span>Перенести в активный сервер</span>
            </button>
            <button onclick="downloadFmZip('')" class="px-3 py-2 rounded-xl bg-[#1a1d28] hover:bg-[#25293a] border border-[#2a3044] text-xs font-bold text-slate-200 transition-all flex items-center gap-2" title="Скачать всю папку сервера в ZIP">
              <i class="fa-solid fa-file-zipper text-emerald-400"></i>
              <span>ZIP сервера</span>
            </button>
            <button id="fmDeleteServerBtn" onclick="openDeleteServerModal()" class="hidden px-3 py-2 rounded-xl bg-red-950/40 hover:bg-red-900/60 border border-red-800/50 text-xs font-bold text-red-300 transition-all flex items-center gap-2" title="Удалить архивный сервер с диска">
              <i class="fa-solid fa-trash-can"></i>
              <span>Удалить архив</span>
            </button>
          </div>
        </div>

        <!-- Archive Notice Banner -->
        <div id="fmArchiveBanner" class="hidden p-3.5 rounded-xl bg-gradient-to-r from-amber-950/40 to-orange-950/20 border border-amber-800/40 text-xs text-amber-200/90 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div class="flex items-center gap-3">
            <i class="fa-solid fa-box-archive text-amber-400 text-lg"></i>
            <div>
              <span class="font-bold text-amber-300">Архивный сервер на диске:</span>
              <span class="text-slate-300 ml-1">Эта сборка сохранена в локальной директории, но отсутствует в DiscoPanel. Вы можете скачивать шейдеры/моды или перенести их в 1 клик.</span>
            </div>
          </div>
          <button onclick="openMigrateModal()" class="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs shrink-0 transition-all">
            ⚡ Перенести ресурсы
          </button>
        </div>
      </div>

      <!-- Explorer Controls & Breadcrumbs -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#11131a] border border-[#1b1e2a] px-4 py-3 rounded-2xl">
        <!-- Breadcrumbs -->
        <div id="fmBreadcrumbs" class="flex items-center gap-1.5 text-xs text-slate-400 font-mono overflow-x-auto whitespace-nowrap py-1">
          <button onclick="loadFmDirectory('')" class="hover:text-amber-400 transition-colors flex items-center gap-1">
            <i class="fa-solid fa-house text-amber-400"></i>
            <span>root</span>
          </button>
        </div>

        <!-- Action Buttons -->
        <div class="flex flex-wrap items-center gap-2 shrink-0">
          <div class="relative">
            <input type="text" id="fmSearchInput" oninput="filterFmItems(this.value)" placeholder="Поиск в папке..." class="bg-[#0b0c11] border border-slate-700/70 rounded-xl px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-amber-500 focus:outline-none w-36 sm:w-48 pl-7">
            <i class="fa-solid fa-magnifying-glass absolute left-2.5 top-2.5 text-[10px] text-slate-500"></i>
          </div>
          <button onclick="goFmUp()" id="fmUpBtn" class="px-2.5 py-1.5 rounded-xl bg-[#1a1d28] hover:bg-[#25293a] border border-[#2a3044] text-xs text-slate-300 transition-all" title="Наверх">
            <i class="fa-solid fa-arrow-up"></i>
          </button>
          <button onclick="openCreateFolderModal()" class="px-3 py-1.5 rounded-xl bg-[#1a1d28] hover:bg-[#25293a] border border-[#2a3044] text-xs font-semibold text-slate-200 transition-all flex items-center gap-1.5" title="Создать новую папку">
            <i class="fa-solid fa-folder-plus text-amber-400"></i>
            <span class="hidden sm:inline">Новая папка</span>
          </button>
          <label class="px-3 py-1.5 rounded-xl bg-emerald-600/90 hover:bg-emerald-500 text-xs font-bold text-white transition-all flex items-center gap-1.5 cursor-pointer shadow-md shadow-emerald-950/40">
            <i class="fa-solid fa-cloud-arrow-up"></i>
            <span>Загрузить</span>
            <input type="file" id="fmFileInput" multiple onchange="onFmFileSelected(event)" class="hidden">
          </label>
          <button onclick="downloadFmZip(fmCurrentPath)" class="px-2.5 py-1.5 rounded-xl bg-[#1a1d28] hover:bg-[#25293a] border border-[#2a3044] text-xs text-slate-300 transition-all" title="Скачать текущую папку в ZIP">
            <i class="fa-solid fa-file-zipper text-emerald-400"></i>
          </button>
        </div>
      </div>

      <!-- Drag & Drop Zone / File Table Container -->
      <div id="fmDropZone" ondragover="onFmDragOver(event)" ondragleave="onFmDragLeave(event)" ondrop="onFmDrop(event)" class="rounded-2xl border border-[#1b1e2a] bg-[#11131a] overflow-hidden shadow-xl transition-all relative">
        <div id="fmDropOverlay" class="hidden absolute inset-0 bg-amber-500/10 backdrop-blur-sm border-2 border-dashed border-amber-500 z-20 flex flex-col items-center justify-center pointer-events-none">
          <i class="fa-solid fa-cloud-arrow-up text-4xl text-amber-400 mb-2 animate-bounce"></i>
          <span class="text-sm font-bold text-white">Перетащите файлы сюда для загрузки</span>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-[#0c0d12] border-b border-[#1b1e2a] text-[11px] font-bold text-slate-400 uppercase tracking-wider">
              <tr>
                <th class="py-3 px-4">Имя файла / папки</th>
                <th class="py-3 px-4 w-32">Тип</th>
                <th class="py-3 px-4 w-28 text-right">Размер</th>
                <th class="py-3 px-4 w-44">Изменено</th>
                <th class="py-3 px-4 w-36 text-right">Действия</th>
              </tr>
            </thead>
            <tbody id="fmTableBody" class="divide-y divide-[#161822]">
              <tr>
                <td colspan="5" class="py-8 text-center text-slate-500">
                  <i class="fa-solid fa-circle-notch fa-spin text-lg mb-2"></i>
                  <div>Загрузка содержимого...</div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

    </div>

  </main>

  <!-- ================= MODAL: CHANGE ADMIN CREDENTIALS ================= -->
  <div id="credentialsModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm hidden">
    <div class="bg-[#11131a] border border-[#222738] rounded-2xl p-6 max-w-md w-full mx-4 shadow-2xl space-y-4">
      <div class="flex items-center justify-between pb-3 border-b border-slate-800">
        <div class="flex items-center gap-2 text-white font-bold text-sm">
          <i class="fa-solid fa-shield-halved text-emerald-400"></i>
          <span>Change Admin Credentials</span>
        </div>
        <button type="button" onclick="closeCredentialsModal()" class="text-slate-400 hover:text-white text-sm p-1">
          <i class="fa-solid fa-xmark"></i>
        </button>
      </div>

      <form onsubmit="saveCredentials(event)" class="space-y-3.5">
        <div>
          <label class="text-[11px] font-semibold text-slate-400 block mb-1">Current Password</label>
          <input type="password" id="currentPassInput" required placeholder="Enter current password" class="w-full bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none">
        </div>

        <div class="pt-2 border-t border-slate-800/60">
          <label class="text-[11px] font-semibold text-slate-400 block mb-1">New Username</label>
          <input type="text" id="newUsernameInput" value="${currentAdminUser}" required placeholder="Admin username" class="w-full bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none font-mono">
        </div>

        <div>
          <label class="text-[11px] font-semibold text-slate-400 block mb-1">New Password</label>
          <input type="password" id="newPassInput" required placeholder="Minimum 4 characters" class="w-full bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none">
        </div>

        <div>
          <label class="text-[11px] font-semibold text-slate-400 block mb-1">Confirm New Password</label>
          <input type="password" id="confirmPassInput" required placeholder="Repeat new password" class="w-full bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none">
        </div>

        <div id="credError" class="hidden p-2.5 rounded-xl bg-red-950/50 border border-red-800/50 text-xs text-red-300"></div>
        <div id="credSuccess" class="hidden p-2.5 rounded-xl bg-emerald-950/50 border border-emerald-800/50 text-xs text-emerald-300"></div>

        <div class="flex items-center justify-end gap-2.5 pt-2">
          <button type="button" onclick="closeCredentialsModal()" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-bold text-slate-300 transition-all">
            Cancel
          </button>
          <button type="submit" id="saveCredBtn" class="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-xs font-bold text-white transition-all shadow-md">
            Save
          </button>
        </div>
      </form>
    </div>
  </div>

  <!-- ================= MODAL: MIGRATE RESOURCES FROM ARCHIVE ================= -->
  <div id="fmMigrateModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm hidden">
    <div class="bg-[#11131a] border border-[#222738] rounded-2xl p-6 max-w-lg w-full mx-4 shadow-2xl space-y-4">
      <div class="flex items-center justify-between pb-3 border-b border-slate-800">
        <div class="flex items-center gap-2 text-white font-bold text-sm">
          <i class="fa-solid fa-bolt text-amber-400"></i>
          <span>Перенос ресурсов в активный сервер</span>
        </div>
        <button type="button" onclick="closeMigrateModal()" class="text-slate-400 hover:text-white text-sm p-1">
          <i class="fa-solid fa-xmark"></i>
        </button>
      </div>

      <div class="space-y-4 text-xs">
        <div>
          <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">Источник (Архивный сервер)</div>
          <div id="fmMigrateSourceName" class="font-mono text-amber-400 bg-[#0b0c11] border border-slate-800 rounded-xl px-3 py-2"></div>
        </div>

        <div>
          <label class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">Куда перенести (Целевой активный сервер)</label>
          <select id="fmMigrateTargetSelect" class="w-full bg-[#0b0c11] border border-slate-700 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none"></select>
        </div>

        <div class="space-y-2 pt-2 border-t border-slate-800/80">
          <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">Что скопировать:</div>
          <label class="flex items-center gap-2.5 p-2 rounded-xl bg-[#0b0c11] border border-slate-800/60 cursor-pointer hover:border-slate-700">
            <input type="checkbox" id="fmMigrateShaders" checked class="w-4 h-4 rounded text-amber-500 bg-slate-900 border-slate-700">
            <div>
              <div class="font-bold text-slate-200">Шейдерпаки (shaderpacks/)</div>
              <div class="text-[10px] text-slate-500">Все шейдеры из архивного сервера</div>
            </div>
          </label>
          <label class="flex items-center gap-2.5 p-2 rounded-xl bg-[#0b0c11] border border-slate-800/60 cursor-pointer hover:border-slate-700">
            <input type="checkbox" id="fmMigrateRp" checked class="w-4 h-4 rounded text-amber-500 bg-slate-900 border-slate-700">
            <div>
              <div class="font-bold text-slate-200">Ресурспаки (resourcepacks/)</div>
              <div class="text-[10px] text-slate-500">Все текстуры и ресурспаки</div>
            </div>
          </label>
          <label class="flex items-center gap-2.5 p-2 rounded-xl bg-[#0b0c11] border border-slate-800/60 cursor-pointer hover:border-slate-700">
            <input type="checkbox" id="fmMigrateClientMods" checked class="w-4 h-4 rounded text-amber-500 bg-slate-900 border-slate-700">
            <div>
              <div class="font-bold text-slate-200">Клиентские моды (client_mods.json)</div>
              <div class="text-[10px] text-slate-500">Моды для оптимизации/интерфейса (Iris, Sodium, ModMenu и т.д.)</div>
            </div>
          </label>
          <label class="flex items-center gap-2.5 p-2 rounded-xl bg-[#0b0c11] border border-slate-800/60 cursor-pointer hover:border-slate-700">
            <input type="checkbox" id="fmMigrateAllMods" class="w-4 h-4 rounded text-amber-500 bg-slate-900 border-slate-700">
            <div>
              <div class="font-bold text-slate-200">Все моды сервера (mods/)</div>
              <div class="text-[10px] text-slate-500">Скопировать абсолютно все .jar файлы из папки mods</div>
            </div>
          </label>
        </div>

        <div class="flex items-center justify-end gap-2.5 pt-3">
          <button type="button" onclick="closeMigrateModal()" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-bold text-slate-300 transition-all">
            Отмена
          </button>
          <button type="button" id="fmMigrateConfirmBtn" onclick="executeMigrateSubmit()" class="px-4 py-2 rounded-xl bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-xs font-bold text-white transition-all shadow-md">
            Начать перенос
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- ================= MODAL: DELETE ARCHIVE SERVER ================= -->
  <div id="fmDeleteServerModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm hidden">
    <div class="bg-[#11131a] border border-red-900/40 rounded-2xl p-6 max-w-md w-full mx-4 shadow-2xl space-y-4">
      <div class="flex items-center justify-between pb-3 border-b border-slate-800">
        <div class="flex items-center gap-2 text-red-400 font-bold text-sm">
          <i class="fa-solid fa-triangle-exclamation"></i>
          <span>Удаление архивного сервера</span>
        </div>
        <button type="button" onclick="closeDeleteServerModal()" class="text-slate-400 hover:text-white text-sm p-1">
          <i class="fa-solid fa-xmark"></i>
        </button>
      </div>

      <div class="space-y-3 text-xs">
        <p class="text-slate-300">
          Вы собираетесь безвозвратно удалить папку архивного сервера с диска:
        </p>
        <div id="fmDeleteServerConfirmId" class="p-2 rounded-lg bg-red-950/40 border border-red-800/40 font-mono text-red-300 select-all font-bold"></div>
        <p class="text-slate-400 text-[11px]">
          Для подтверждения введите точный идентификатор сервера ниже:
        </p>
        <input type="text" id="fmDeleteServerInput" placeholder="Введите ID сервера" class="w-full bg-[#0b0c11] border border-red-800/50 rounded-xl px-3 py-2 text-xs text-slate-200 font-mono focus:border-red-500 focus:outline-none">

        <div class="flex items-center justify-end gap-2.5 pt-2">
          <button type="button" onclick="closeDeleteServerModal()" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-bold text-slate-300 transition-all">
            Отмена
          </button>
          <button type="button" onclick="executeDeleteServerSubmit()" class="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-xs font-bold text-white transition-all shadow-md">
            Удалить навсегда
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- ================= SCRIPTS ================= -->
  <script>
    (function() {
      const origFetch = window.fetch;
      window.fetch = function(url, options) {
        options = options || {};
        try {
          const token = localStorage.getItem('admin_token');
          if (token) {
            options.headers = options.headers || {};
            if (!(options.headers instanceof Headers) && !options.headers['Authorization']) {
              options.headers['Authorization'] = 'Bearer ' + token;
            }
          }
        } catch(e) {}
        return origFetch(url, options);
      };
    })();

    function switchNav(nav) {
      const sections = ['servers', 'settings', 'dashboard', 'api', 'files'];
      sections.forEach(s => {
        const el = document.getElementById('section_' + s);
        const navEl = document.getElementById('nav_' + s);
        if (el) el.classList.toggle('hidden', s !== nav);
        if (navEl) {
          if (s === nav) {
            navEl.className = "w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-bold text-white bg-[#151824] border border-[#222738] shadow-sm transition-all";
          } else {
            navEl.className = "w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-[#12141c] transition-all";
          }
        }
      });
      try { localStorage.setItem('discopanel_active_nav', nav); } catch(e) {}
      if (nav === 'files') {
        initFileManager();
      }
    }

    // =========================================================================
    // FILE MANAGER FRONTEND CLIENT
    // =========================================================================
    let fmServers = [];
    let fmCurrentServerId = '';
    let fmCurrentPath = '';
    let fmCurrentItems = [];

    async function initFileManager() {
      if (fmServers.length === 0) {
        await loadFmServers();
      } else if (!fmCurrentServerId && fmServers.length > 0) {
        fmCurrentServerId = fmServers[0].id;
        await loadFmDirectory('');
      }
    }

    async function loadFmServers() {
      try {
        const res = await fetch('/api/admin/fs/servers');
        const data = await res.json();
        if (!data.success) {
          console.error('Failed to load servers:', data.error);
          return;
        }
        fmServers = data.servers || [];
        renderFmServerSelect();
        if (fmServers.length > 0) {
          if (!fmCurrentServerId || !fmServers.some(function(s) { return s.id === fmCurrentServerId; })) {
            fmCurrentServerId = fmServers[0].id;
          }
          const sel = document.getElementById('fmServerSelect');
          if (sel) sel.value = fmCurrentServerId;
          updateFmServerHeader();
          await loadFmDirectory('');
        }
      } catch (err) {
        console.error('Error loading servers for FM:', err);
      }
    }

    function renderFmServerSelect() {
      const sel = document.getElementById('fmServerSelect');
      if (!sel) return;
      sel.innerHTML = '';

      const activeList = fmServers.filter(function(s) { return s.isActive; });
      const archiveList = fmServers.filter(function(s) { return !s.isActive; });

      if (activeList.length > 0) {
        const grp = document.createElement('optgroup');
        grp.label = '🟢 Активные серверы (В лаунчере)';
        activeList.forEach(function(s) {
          const opt = document.createElement('option');
          opt.value = s.id;
          opt.textContent = s.name + ' (' + s.id.substring(0, 8) + '...)';
          grp.appendChild(opt);
        });
        sel.appendChild(grp);
      }

      if (archiveList.length > 0) {
        const grp = document.createElement('optgroup');
        grp.label = '📦 Архивные серверы на диске';
        archiveList.forEach(function(s) {
          const opt = document.createElement('option');
          opt.value = s.id;
          opt.textContent = '[Архив] ' + s.name + ' (' + s.modsCount + ' модов, ' + s.shadersCount + ' шейдеров)';
          grp.appendChild(opt);
        });
        sel.appendChild(grp);
      }
    }

    function onFmServerChange() {
      const sel = document.getElementById('fmServerSelect');
      fmCurrentServerId = sel.value;
      updateFmServerHeader();
      loadFmDirectory('');
    }

    function updateFmServerHeader() {
      const srv = fmServers.find(function(s) { return s.id === fmCurrentServerId; });
      const badge = document.getElementById('fmServerBadge');
      const stats = document.getElementById('fmServerStats');
      const banner = document.getElementById('fmArchiveBanner');
      const migrateBtn = document.getElementById('fmMigrateBtn');
      const deleteServerBtn = document.getElementById('fmDeleteServerBtn');

      if (!srv) return;

      if (srv.isActive) {
        badge.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold text-xs';
        badge.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span><span>Активен в панели</span>';
        badge.classList.remove('hidden');
        banner.classList.add('hidden');
        migrateBtn.classList.add('hidden');
        deleteServerBtn.classList.add('hidden');
      } else {
        badge.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 font-bold text-xs';
        badge.innerHTML = '<i class="fa-solid fa-box-archive"></i><span>Архив на диске</span>';
        badge.classList.remove('hidden');
        banner.classList.remove('hidden');
        migrateBtn.classList.remove('hidden');
        deleteServerBtn.classList.remove('hidden');
      }

      stats.innerHTML = '<span class="px-2 py-0.5 rounded bg-[#161925] border border-[#23283c] font-mono text-[11px] text-slate-300"><b>' + srv.modsCount + '</b> модов</span>' +
        '<span class="px-2 py-0.5 rounded bg-[#161925] border border-[#23283c] font-mono text-[11px] text-slate-300"><b>' + srv.shadersCount + '</b> шейдеров</span>' +
        '<span class="px-2 py-0.5 rounded bg-[#161925] border border-[#23283c] font-mono text-[11px] text-slate-300"><b>' + srv.rpCount + '</b> паков</span>';
    }

    async function loadFmDirectory(subpath) {
      if (!fmCurrentServerId) return;
      fmCurrentPath = subpath || '';
      renderFmBreadcrumbs();

      const tbody = document.getElementById('fmTableBody');
      tbody.innerHTML = '<tr><td colspan="5" class="py-10 text-center text-slate-500">' +
        '<i class="fa-solid fa-circle-notch fa-spin text-xl text-amber-400 mb-2"></i>' +
        '<div>Загрузка содержимого папки...</div>' +
        '</td></tr>';

      try {
        const res = await fetch('/api/admin/fs/list?serverId=' + encodeURIComponent(fmCurrentServerId) + '&subpath=' + encodeURIComponent(fmCurrentPath));
        const data = await res.json();
        if (!data.success) {
          tbody.innerHTML = '<tr><td colspan="5" class="py-8 text-center text-red-400">' +
            '<i class="fa-solid fa-triangle-exclamation text-xl mb-1"></i>' +
            '<div>Ошибка: ' + escapeHtml(data.error || 'Не удалось прочитать папку') + '</div>' +
            '</td></tr>';
          return;
        }

        fmCurrentItems = data.items || [];
        renderFmTable(fmCurrentItems);
      } catch (err) {
        tbody.innerHTML = '<tr><td colspan="5" class="py-8 text-center text-red-400">' +
          '<i class="fa-solid fa-triangle-exclamation text-xl mb-1"></i>' +
          '<div>Сетевая ошибка: ' + escapeHtml(err.message) + '</div>' +
          '</td></tr>';
      }
    }

    function renderFmBreadcrumbs() {
      const container = document.getElementById('fmBreadcrumbs');
      if (!container) return;

      const srv = fmServers.find(function(s) { return s.id === fmCurrentServerId; });
      const serverTitle = srv ? srv.name : fmCurrentServerId;

      let html = '<button onclick="loadFmDirectory()" class="hover:text-amber-400 transition-colors flex items-center gap-1.5 font-bold text-slate-200">' +
        '<i class="fa-solid fa-server text-indigo-400"></i>' +
        '<span>' + escapeHtml(serverTitle) + '</span>' +
        '</button>';

      if (fmCurrentPath) {
        const parts = fmCurrentPath.split('/').filter(Boolean);
        let accumulated = '';
        for (let i = 0; i < parts.length; i++) {
          accumulated += (accumulated ? '/' : '') + parts[i];
          const isLast = (i === parts.length - 1);
          const currentAccum = accumulated;
          html += '<span class="text-slate-600">/</span>' +
            '<button onclick="loadFmDirectory(this.dataset.path)" data-path="' + escapeHtml(currentAccum) + '" class="' + (isLast ? 'text-amber-400 font-bold' : 'text-slate-400 hover:text-white') + ' transition-colors">' +
            escapeHtml(parts[i]) +
            '</button>';
        }
      }
      container.innerHTML = html;

      const upBtn = document.getElementById('fmUpBtn');
      if (upBtn) {
        upBtn.disabled = !fmCurrentPath;
        upBtn.className = !fmCurrentPath ? 'px-2.5 py-1.5 rounded-xl bg-[#141620] border border-[#1d2130] text-xs text-slate-600 cursor-not-allowed' : 'px-2.5 py-1.5 rounded-xl bg-[#1a1d28] hover:bg-[#25293a] border border-[#2a3044] text-xs text-slate-300 transition-all';
      }
    }

    function goFmUp() {
      if (!fmCurrentPath) return;
      const parts = fmCurrentPath.split('/').filter(Boolean);
      parts.pop();
      loadFmDirectory(parts.join('/'));
    }

    function filterFmItems(q) {
      const query = (q || '').toLowerCase().trim();
      if (!query) {
        renderFmTable(fmCurrentItems);
        return;
      }
      const filtered = fmCurrentItems.filter(function(item) { return item.name.toLowerCase().includes(query); });
      renderFmTable(filtered);
    }

    function renderFmTable(items) {
      const tbody = document.getElementById('fmTableBody');
      if (!tbody) return;

      if (!items || items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="py-10 text-center text-slate-500">' +
          '<i class="fa-regular fa-folder-open text-3xl mb-2 text-slate-600"></i>' +
          '<div>В этой папке пусто</div>' +
          '</td></tr>';
        return;
      }

      let html = '';
      items.forEach(function(item) {
        const itemPath = fmCurrentPath ? (fmCurrentPath + '/' + item.name) : item.name;

        let icon = 'fa-file text-slate-400';
        let typeBadge = item.ext || 'файл';

        if (item.isDir) {
          icon = 'fa-folder text-amber-400';
          typeBadge = 'папка';
        } else if (item.ext === '.jar') {
          icon = 'fa-cube text-indigo-400';
          typeBadge = 'мод (.jar)';
        } else if (item.ext === '.zip') {
          icon = 'fa-file-zipper text-emerald-400';
          typeBadge = 'архив (.zip)';
        } else if (['.json', '.toml', '.yml', '.yaml', '.properties', '.cfg', '.txt', '.log'].includes(item.ext)) {
          icon = 'fa-file-code text-cyan-400';
        } else if (['.png', '.jpg', '.jpeg', '.webp'].includes(item.ext)) {
          icon = 'fa-file-image text-pink-400';
        }

        const sizeStr = item.isDir ? '-' : formatBytes(item.size);
        const dateStr = item.mtime ? new Date(item.mtime).toLocaleString('ru-RU') : '-';

        html += '<tr class="hover:bg-[#141722] transition-colors group">' +
          '<td class="py-2.5 px-4 font-medium">' +
          '<div class="flex items-center gap-2.5">' +
          '<i class="fa-solid ' + icon + ' text-sm w-4 text-center shrink-0"></i>';

        if (item.isDir) {
          html += '<button onclick="loadFmDirectory(this.dataset.path)" data-path="' + escapeHtml(itemPath) + '" class="text-slate-200 hover:text-amber-400 font-semibold transition-colors truncate text-left">' +
            escapeHtml(item.name) +
            '</button>';
        } else {
          html += '<span class="text-slate-300 truncate">' + escapeHtml(item.name) + '</span>';
        }

        html += '</div></td>' +
          '<td class="py-2.5 px-4 text-slate-500 font-mono text-[11px]">' + typeBadge + '</td>' +
          '<td class="py-2.5 px-4 text-right text-slate-400 font-mono text-[11px]">' + sizeStr + '</td>' +
          '<td class="py-2.5 px-4 text-slate-500 font-mono text-[11px]">' + dateStr + '</td>' +
          '<td class="py-2.5 px-4 text-right">' +
          '<div class="flex items-center justify-end gap-1.5 opacity-80 group-hover:opacity-100 transition-opacity">';

        if (item.isDir) {
          html += '<button onclick="loadFmDirectory(this.dataset.path)" data-path="' + escapeHtml(itemPath) + '" class="p-1.5 rounded-lg bg-[#1a1d28] hover:bg-[#25293a] text-slate-300 hover:text-white transition-all" title="Открыть папку">' +
            '<i class="fa-solid fa-arrow-right-to-bracket text-xs"></i>' +
            '</button>' +
            '<button onclick="downloadFmZip(this.dataset.path)" data-path="' + escapeHtml(itemPath) + '" class="p-1.5 rounded-lg bg-[#1a1d28] hover:bg-[#25293a] text-emerald-400 hover:text-emerald-300 transition-all" title="Скачать папку как ZIP">' +
            '<i class="fa-solid fa-file-zipper text-xs"></i>' +
            '</button>' +
            '<button onclick="deleteFmItem(this.dataset.path, true)" data-path="' + escapeHtml(itemPath) + '" class="p-1.5 rounded-lg bg-red-950/30 hover:bg-red-900/50 text-red-400 transition-all" title="Удалить папку">' +
            '<i class="fa-solid fa-trash-can text-xs"></i>' +
            '</button>';
        } else {
          html += '<button onclick="downloadFmFile(this.dataset.path)" data-path="' + escapeHtml(itemPath) + '" class="p-1.5 rounded-lg bg-[#1a1d28] hover:bg-[#25293a] text-emerald-400 hover:text-emerald-300 transition-all" title="Скачать файл">' +
            '<i class="fa-solid fa-download text-xs"></i>' +
            '</button>' +
            '<button onclick="deleteFmItem(this.dataset.path, false)" data-path="' + escapeHtml(itemPath) + '" class="p-1.5 rounded-lg bg-red-950/30 hover:bg-red-900/50 text-red-400 transition-all" title="Удалить файл">' +
            '<i class="fa-solid fa-trash-can text-xs"></i>' +
            '</button>';
        }

        html += '</div></td></tr>';
      });

      tbody.innerHTML = html;
    }

    function downloadFmFile(filepath) {
      const token = localStorage.getItem('admin_token') || '';
      window.location.href = '/api/admin/fs/download?serverId=' + encodeURIComponent(fmCurrentServerId) + '&filepath=' + encodeURIComponent(filepath) + '&auth_token=' + encodeURIComponent(token);
    }

    function downloadFmZip(subpath) {
      const token = localStorage.getItem('admin_token') || '';
      window.location.href = '/api/admin/fs/download-zip?serverId=' + encodeURIComponent(fmCurrentServerId) + '&subpath=' + encodeURIComponent(subpath || '') + '&auth_token=' + encodeURIComponent(token);
    }

    async function deleteFmItem(filepath, isDir) {
      const itemType = isDir ? 'папку со всем содержимым' : 'файл';
      if (!confirm('Вы уверены, что хотите удалить ' + itemType + ' "' + filepath + '"?')) return;

      try {
        const res = await fetch('/api/admin/fs/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serverId: fmCurrentServerId, filepath: filepath })
        });
        const data = await res.json();
        if (data.success) {
          loadFmDirectory(fmCurrentPath);
        } else {
          alert('Ошибка удаления: ' + (data.error || 'Неизвестная ошибка'));
        }
      } catch (err) {
        alert('Сетевая ошибка: ' + err.message);
      }
    }

    async function onFmFileSelected(e) {
      const files = e.target.files;
      if (!files || files.length === 0) return;
      await uploadFmFiles(files);
      e.target.value = '';
    }

    async function uploadFmFiles(fileList) {
      const token = localStorage.getItem('admin_token') || '';
      const formData = new FormData();
      for (let i = 0; i < fileList.length; i++) {
        formData.append('files', fileList[i]);
      }

      const tbody = document.getElementById('fmTableBody');
      tbody.innerHTML = '<tr><td colspan="5" class="py-10 text-center text-amber-400">' +
        '<i class="fa-solid fa-cloud-arrow-up fa-bounce text-2xl mb-2"></i>' +
        '<div>Загрузка ' + fileList.length + ' файла(ов)... Пожалуйста, подождите</div>' +
        '</td></tr>';

      try {
        const res = await fetch('/api/admin/fs/upload?serverId=' + encodeURIComponent(fmCurrentServerId) + '&subpath=' + encodeURIComponent(fmCurrentPath) + '&auth_token=' + encodeURIComponent(token), {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        if (data.success) {
          await loadFmDirectory(fmCurrentPath);
        } else {
          alert('Ошибка загрузки: ' + (data.error || 'Сбой'));
          await loadFmDirectory(fmCurrentPath);
        }
      } catch (err) {
        alert('Сетевая ошибка при загрузке: ' + err.message);
        await loadFmDirectory(fmCurrentPath);
      }
    }

    function onFmDragOver(e) {
      e.preventDefault();
      document.getElementById('fmDropOverlay').classList.remove('hidden');
    }

    function onFmDragLeave(e) {
      e.preventDefault();
      document.getElementById('fmDropOverlay').classList.add('hidden');
    }

    async function onFmDrop(e) {
      e.preventDefault();
      document.getElementById('fmDropOverlay').classList.add('hidden');
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        await uploadFmFiles(e.dataTransfer.files);
      }
    }

    function openCreateFolderModal() {
      const name = prompt('Введите имя новой папки:');
      if (!name || !name.trim()) return;
      createFolderSubmit(name.trim());
    }

    async function createFolderSubmit(dirName) {
      try {
        const res = await fetch('/api/admin/fs/mkdir', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            serverId: fmCurrentServerId,
            subpath: fmCurrentPath,
            dirName: dirName
          })
        });
        const data = await res.json();
        if (data.success) {
          loadFmDirectory(fmCurrentPath);
        } else {
          alert('Ошибка создания папки: ' + (data.error || 'Ошибка'));
        }
      } catch (err) {
        alert('Сетевая ошибка: ' + err.message);
      }
    }

    function openMigrateModal() {
      const modal = document.getElementById('fmMigrateModal');
      const srcNameEl = document.getElementById('fmMigrateSourceName');
      const targetSel = document.getElementById('fmMigrateTargetSelect');

      const srv = fmServers.find(function(s) { return s.id === fmCurrentServerId; });
      srcNameEl.textContent = srv ? (srv.name + ' (' + srv.id + ')') : fmCurrentServerId;

      targetSel.innerHTML = '';
      const activeServers = fmServers.filter(function(s) { return s.isActive && s.id !== fmCurrentServerId; });
      if (activeServers.length === 0) {
        targetSel.innerHTML = '<option value="">Нет других активных серверов</option>';
      } else {
        activeServers.forEach(function(s) {
          const opt = document.createElement('option');
          opt.value = s.id;
          opt.textContent = s.name + ' (' + s.id + ')';
          targetSel.appendChild(opt);
        });
      }

      modal.classList.remove('hidden');
    }

    function closeMigrateModal() {
      document.getElementById('fmMigrateModal').classList.add('hidden');
    }

    async function executeMigrateSubmit() {
      const targetServerId = document.getElementById('fmMigrateTargetSelect').value;
      if (!targetServerId) {
        alert('Выберите целевой сервер');
        return;
      }

      const copyShaders = document.getElementById('fmMigrateShaders').checked;
      const copyResourcepacks = document.getElementById('fmMigrateRp').checked;
      const copyClientMods = document.getElementById('fmMigrateClientMods').checked;
      const copyAllMods = document.getElementById('fmMigrateAllMods').checked;

      if (!copyShaders && !copyResourcepacks && !copyClientMods && !copyAllMods) {
        alert('Выберите хотя бы один пункт для переноса');
        return;
      }

      const btn = document.getElementById('fmMigrateConfirmBtn');
      const origText = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Копирование...';

      try {
        const res = await fetch('/api/admin/fs/migrate-archive', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sourceServerId: fmCurrentServerId,
            targetServerId: targetServerId,
            options: { copyShaders: copyShaders, copyResourcepacks: copyResourcepacks, copyClientMods: copyClientMods, copyAllMods: copyAllMods }
          })
        });
        const data = await res.json();
        if (data.success) {
          alert('Перенос успешно выполнен! ' + data.message);
          closeMigrateModal();
          await loadFmServers();
        } else {
          alert('Ошибка переноса: ' + (data.error || 'Сбой'));
        }
      } catch (err) {
        alert('Сетевая ошибка: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.innerHTML = origText;
      }
    }

    function openDeleteServerModal() {
      const modal = document.getElementById('fmDeleteServerModal');
      document.getElementById('fmDeleteServerConfirmId').textContent = fmCurrentServerId;
      document.getElementById('fmDeleteServerInput').value = '';
      modal.classList.remove('hidden');
    }

    function closeDeleteServerModal() {
      document.getElementById('fmDeleteServerModal').classList.add('hidden');
    }

    async function executeDeleteServerSubmit() {
      const input = document.getElementById('fmDeleteServerInput').value.trim();
      if (input !== fmCurrentServerId) {
        alert('Введенное значение не совпадает с идентификатором сервера!');
        return;
      }

      try {
        const res = await fetch('/api/admin/fs/delete-server', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            serverId: fmCurrentServerId,
            confirmText: input
          })
        });
        const data = await res.json();
        if (data.success) {
          alert('Архивный сервер успешно удален с диска');
          closeDeleteServerModal();
          fmCurrentServerId = '';
          await loadFmServers();
        } else {
          alert('Ошибка при удалении: ' + (data.error || 'Сбой'));
        }
      } catch (err) {
        alert('Сетевая ошибка: ' + err.message);
      }
    }

    function formatBytes(bytes) {
      if (!bytes || bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    // Auto-refresh live server online stats
    async function refreshLiveStats() {
      try {
        const res = await fetch('/api/admin/live-stats');
        const data = await res.json();
        if (data.success && data.servers) {
          data.servers.forEach(function(s) {
            const onEl = document.getElementById('serverOnline_' + s.id);
            const maxEl = document.getElementById('serverMaxOnline_' + s.id);
            if (onEl) onEl.textContent = s.online;
            if (maxEl) maxEl.textContent = s.maxOnline;
          });
          const dashEl = document.getElementById('dashTotalPlayersOnline');
          if (dashEl) dashEl.textContent = data.totalPlayersOnline;
        }
      } catch(e) {}
    }
    setInterval(refreshLiveStats, 6000);

    try {
      const savedNav = localStorage.getItem('discopanel_active_nav');
      if (savedNav) switchNav(savedNav);
    } catch(e) {}

    function filterServers(query) {
      const q = (query || '').toLowerCase().trim();
      const cards = document.querySelectorAll('[id^="serverCard_"]');
      cards.forEach(card => {
        const text = card.getAttribute('data-search') || '';
        card.style.display = text.includes(q) ? '' : 'none';
      });
    }

    function filterModRows(serverId, query) {
      const q = (query || '').toLowerCase().trim();
      const rows = document.querySelectorAll('#srvTab_' + serverId + '_mods [id^="modRow_' + serverId + '_"]');
      rows.forEach(r => {
        const name = r.getAttribute('data-name') || '';
        r.style.display = name.includes(q) ? '' : 'none';
      });
    }

    function switchServerTab(serverId, tab) {
      const tabs = ['mods', 'shaders', 'resourcepacks', 'host'];
      tabs.forEach(t => {
        const pane = document.getElementById('srvTab_' + serverId + '_' + t);
        const btn = document.getElementById('srvTabBtn_' + serverId + '_' + t);
        if (pane) pane.classList.toggle('hidden', t !== tab);
        if (btn) {
          if (t === tab) {
            btn.className = "px-4 py-1.5 rounded-lg text-xs font-bold flex items-center gap-2 bg-indigo-600 text-white shadow-sm transition-all";
          } else {
            btn.className = "px-4 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white bg-[#12141c] hover:bg-[#1a1d28] transition-all flex items-center gap-1.5";
          }
        }
      });
    }

    function scrollToServer(serverId) {
      switchNav('servers');
      const card = document.getElementById('serverCard_' + serverId);
      if (card) {
        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        card.classList.add('ring-2', 'ring-emerald-500/50');
        setTimeout(() => card.classList.remove('ring-2', 'ring-emerald-500/50'), 2000);
      }
    }

    function toggleServerDetails(serverId) {
      const details = document.getElementById('details_' + serverId);
      const arrow = document.getElementById('toggleArrow_' + serverId);
      if (details) {
        const isHidden = details.classList.contains('hidden');
        details.classList.toggle('hidden', !isHidden);
        if (arrow) {
          arrow.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0deg)';
        }
      }
    }

    async function toggleMod(serverId, filename, enabled) {
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/toggle-mod', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename, enabled })
        });
        const d = await res.json();
        if (!d.success) {
          alert('Failed to toggle mod: ' + (d.error || 'Error'));
        } else {
          const rowTitle = document.getElementById('modTitle_' + serverId + '_' + encodeURIComponent(filename));
          if (rowTitle) {
            if (enabled) {
              rowTitle.classList.remove('line-through', 'text-slate-500');
              rowTitle.classList.add('text-slate-200');
            } else {
              rowTitle.classList.add('line-through', 'text-slate-500');
              rowTitle.classList.remove('text-slate-200');
            }
          }
        }
      } catch (err) {
        alert('Network error: ' + err.message);
      }
    }

    async function toggleSync(serverId, enabled) {
      try {
        await fetch('/api/admin/servers/' + serverId + '/toggle-sync', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled })
        });
      } catch (e) {}
    }

    async function logoutAdmin() {
      try { localStorage.removeItem('admin_token'); } catch(e) {}
      try { await fetch('/api/logout', { method: 'POST' }); } catch(e) {}
      window.location.href = '/login';
    }

    async function saveApiConfig(e) {
      e.preventDefault();
      const url = document.getElementById('dpUrlInput').value.trim();
      const token = document.getElementById('dpTokenInput').value.trim();
      try {
        const res = await fetch('/api/admin/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ discopanel_url: url, discopanel_token: token })
        });
        const d = await res.json();
        if (d.success) {
          alert('Settings saved successfully!');
          window.location.reload();
        } else {
          alert('Error: ' + (d.error || 'Failed to save settings'));
        }
      } catch (err) {
        alert('Network error: ' + err.message);
      }
    }

    async function triggerSyncNow() {
      try {
        const res = await fetch('/api/admin/sync-api', { method: 'POST' });
        const d = await res.json();
        if (d.success) {
          alert('Server synchronization completed!');
          window.location.reload();
        } else {
          alert('Error: ' + (d.error || 'Sync error'));
        }
      } catch (err) {
        alert('Network error: ' + err.message);
      }
    }

    function copyLauncherUrl() {
      const text = document.getElementById('launcherApiUrl').textContent.trim();
      navigator.clipboard.writeText(text).then(() => {
        const btnText = document.getElementById('copyBtnText');
        const origText = btnText.textContent;
        btnText.textContent = 'Copied!';
        setTimeout(() => { btnText.textContent = origText; }, 2000);
      }).catch(() => {
        const dummy = document.createElement('textarea');
        dummy.value = text;
        document.body.appendChild(dummy);
        dummy.select();
        document.execCommand('copy');
        document.body.removeChild(dummy);
        const btnText = document.getElementById('copyBtnText');
        btnText.textContent = 'Copied!';
        setTimeout(() => { btnText.textContent = 'Copy'; }, 2000);
      });
    }

    async function savePublicHost(serverId) {
      const input = document.getElementById('hostInput_' + serverId);
      const host = input.value.trim();
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/public-host', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host })
        });
        const d = await res.json();
        if (d.success) {
          alert('Public address saved!');
          window.location.reload();
        } else {
          alert('Error: ' + (d.error || 'Failed to save'));
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    async function uploadClientMods(serverId, fileList) {
      if (!fileList || fileList.length === 0) return;
      const formData = new FormData();
      for (let i = 0; i < fileList.length; i++) {
        formData.append('mods', fileList[i]);
      }
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/upload-mod', {
          method: 'POST',
          body: formData
        });
        const d = await res.json();
        if (d.success) {
          alert('Successfully uploaded ' + d.count + ' mod(s)');
          window.location.reload();
        } else {
          alert('Upload error: ' + (d.error || 'Error'));
        }
      } catch (err) {
        alert('Upload error: ' + err.message);
      }
    }

    async function uploadShaders(serverId, fileList) {
      if (!fileList || fileList.length === 0) return;
      const formData = new FormData();
      for (let i = 0; i < fileList.length; i++) {
        formData.append('shaders', fileList[i]);
      }
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/upload-shader', {
          method: 'POST',
          body: formData
        });
        const d = await res.json();
        if (d.success) {
          alert('Successfully uploaded ' + d.count + ' shader(s)');
          window.location.reload();
        } else {
          alert('Upload error: ' + (d.error || 'Error'));
        }
      } catch (err) {
        alert('Upload error: ' + err.message);
      }
    }

    async function deleteShader(serverId, filename) {
      if (!confirm('Delete shader "' + filename + '"?')) return;
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/delete-shader', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename })
        });
        const d = await res.json();
        if (d.success) { window.location.reload(); }
        else { alert('Error: ' + (d.error || 'Error')); }
      } catch (err) { alert('Error: ' + err.message); }
    }

    async function uploadResourcepacks(serverId, fileList) {
      if (!fileList || fileList.length === 0) return;
      const formData = new FormData();
      for (let i = 0; i < fileList.length; i++) {
        formData.append('resourcepacks', fileList[i]);
      }
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/upload-resourcepack', {
          method: 'POST',
          body: formData
        });
        const d = await res.json();
        if (d.success) {
          alert('Successfully uploaded ' + d.count + ' resource pack(s)');
          window.location.reload();
        } else {
          alert('Upload error: ' + (d.error || 'Error'));
        }
      } catch (err) {
        alert('Upload error: ' + err.message);
      }
    }

    async function deleteResourcepack(serverId, filename) {
      if (!confirm('Delete resource pack "' + filename + '"?')) return;
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/delete-resourcepack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename })
        });
        const d = await res.json();
        if (d.success) { window.location.reload(); }
        else { alert('Error: ' + (d.error || 'Error')); }
      } catch (err) { alert('Error: ' + err.message); }
    }

    async function deleteMod(serverId, filename) {
      if (!confirm('Delete client mod "' + filename + '"?')) return;
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/delete-mod', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename })
        });
        const d = await res.json();
        if (d.success) { window.location.reload(); }
        else { alert('Error: ' + (d.error || 'Error')); }
      } catch (err) { alert('Error: ' + err.message); }
    }

    function switchModSubTab(serverId, subtab) {
      const clientPane = document.getElementById('modSubPane_' + serverId + '_client');
      const serverPane = document.getElementById('modSubPane_' + serverId + '_server');
      const clientBtn = document.getElementById('modSubBtn_' + serverId + '_client');
      const serverBtn = document.getElementById('modSubBtn_' + serverId + '_server');
      if (clientPane && serverPane) {
        if (subtab === 'client') {
          clientPane.classList.remove('hidden');
          serverPane.classList.add('hidden');
          if (clientBtn) clientBtn.className = "px-3 py-1.5 rounded-lg text-xs font-bold bg-indigo-600 text-white shadow-sm transition-all flex items-center gap-1.5";
          if (serverBtn) serverBtn.className = "px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white bg-[#12141c] hover:bg-[#1a1d28] transition-all flex items-center gap-1.5";
        } else {
          clientPane.classList.add('hidden');
          serverPane.classList.remove('hidden');
          if (serverBtn) serverBtn.className = "px-3 py-1.5 rounded-lg text-xs font-bold bg-purple-600 text-white shadow-sm transition-all flex items-center gap-1.5";
          if (clientBtn) clientBtn.className = "px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white bg-[#12141c] hover:bg-[#1a1d28] transition-all flex items-center gap-1.5";
        }
      }
    }

    async function importDpMod(serverId, filename) {
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/import-dp-mod', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename })
        });
        const d = await res.json();
        if (d.success) {
          window.location.reload();
        } else {
          alert('Ошибка импорта мода: ' + (d.error || 'Ошибка'));
        }
      } catch (err) {
        alert('Ошибка: ' + err.message);
      }
    }

    async function unimportDpMod(serverId, filename) {
      if (!confirm('Убрать мод "' + filename + '" из списка для игроков? На самом сервере мод останется.')) return;
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/unimport-dp-mod', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename })
        });
        const d = await res.json();
        if (d.success) {
          window.location.reload();
        } else {
          alert('Ошибка: ' + (d.error || 'Ошибка'));
        }
      } catch (err) {
        alert('Ошибка: ' + err.message);
      }
    }

    function filterModRows(serverId, query) {
      const q = (query || '').toLowerCase().trim();
      const panes = ['client', 'server'];
      panes.forEach(paneType => {
        const pane = document.getElementById('modSubPane_' + serverId + '_' + paneType);
        if (!pane) return;
        const rows = pane.querySelectorAll('[id^="modRow_' + serverId + '_"]');
        rows.forEach(r => {
          const name = r.getAttribute('data-name') || '';
          if (!q || name.includes(q)) {
            r.classList.remove('hidden');
          } else {
            r.classList.add('hidden');
          }
        });
      });
    }

    function openCredentialsModal() {
      document.getElementById('credError').classList.add('hidden');
      document.getElementById('credSuccess').classList.add('hidden');
      document.getElementById('currentPassInput').value = '';
      document.getElementById('newPassInput').value = '';
      document.getElementById('confirmPassInput').value = '';
      document.getElementById('credentialsModal').classList.remove('hidden');
    }

    function closeCredentialsModal() {
      document.getElementById('credentialsModal').classList.add('hidden');
    }

    async function saveCredentials(e) {
      e.preventDefault();
      const currentPassword = document.getElementById('currentPassInput').value;
      const newUsername = document.getElementById('newUsernameInput').value.trim();
      const newPassword = document.getElementById('newPassInput').value;
      const confirmPassword = document.getElementById('confirmPassInput').value;

      const errBox = document.getElementById('credError');
      const succBox = document.getElementById('credSuccess');
      errBox.classList.add('hidden');
      succBox.classList.add('hidden');

      if (!newUsername) {
        errBox.textContent = 'Username cannot be empty!';
        errBox.classList.remove('hidden');
        return;
      }
      if (newPassword !== confirmPassword) {
        errBox.textContent = 'New passwords do not match!';
        errBox.classList.remove('hidden');
        return;
      }
      if (newPassword.length < 4) {
        errBox.textContent = 'Password must be at least 4 characters!';
        errBox.classList.remove('hidden');
        return;
      }

      const btn = document.getElementById('saveCredBtn');
      btn.disabled = true;
      btn.textContent = 'Saving...';

      try {
        const res = await fetch('/api/admin/change-credentials', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ currentPassword, newUsername, newPassword })
        });
        const d = await res.json();
        if (d.success) {
          succBox.textContent = 'Credentials updated successfully! Reloading...';
          succBox.classList.remove('hidden');
          setTimeout(() => window.location.reload(), 1200);
        } else {
          errBox.textContent = d.error || 'Failed to update credentials';
          errBox.classList.remove('hidden');
        }
      } catch (err) {
        errBox.textContent = 'Network error: ' + err.message;
        errBox.classList.remove('hidden');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Save';
      }
    }

    try {
      if (window.location.hostname) {
        document.getElementById('launcherApiUrl').textContent = 'http://' + window.location.hostname + ':${LAUNCHER_PORT}';
      }
    } catch(e) {}
  </script>
</body>
</html>`;

  res.send(html);
});

// Admin API endpoints (all protected by requireAdminAuth)
adminApp.get('/api/admin/live-stats', requireAdminAuth, async (req, res) => {
  const servers = db.prepare('SELECT id, name, ip, port, online, max_online, status FROM servers').all();
  const dpUrlSetting = getSetting('discopanel_url', 'http://192.168.10.127:8080');
  const dpTokenSetting = getSetting('discopanel_token');

  // Map of DiscoPanel server data if available
  let dpServersMap = new Map();
  if (dpTokenSetting && dpUrlSetting) {
    try {
      const dpRes = await fetch(`${dpUrlSetting}/discopanel.v1.ServerService/ListServers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${dpTokenSetting}` },
        body: JSON.stringify({}),
        signal: AbortSignal.timeout(2500)
      });
      if (dpRes.ok) {
        const dpData = await dpRes.json();
        (dpData.servers || []).forEach(srv => dpServersMap.set(srv.id, srv));
      }
    } catch(e) {}
  }

  let adminDpHost = '127.0.0.1';
  try { adminDpHost = new URL(dpUrlSetting).hostname; } catch(e) {}

  for (const s of servers) {
    const dpSrv = dpServersMap.get(s.id);
    if (dpSrv && typeof dpSrv.playersOnline === 'number') {
      s.online = dpSrv.playersOnline;
      s.max_online = dpSrv.maxPlayersSlp || dpSrv.maxPlayers || s.max_online || 20;
      s.maxOnline = s.max_online;
      s.playerSample = dpSrv.playerSample || [];
      try {
        db.prepare('UPDATE servers SET online = ?, max_online = ? WHERE id = ?').run(s.online, s.max_online, s.id);
      } catch(e) {}
    } else {
      const customHost = getSetting('public_server_host_' + s.id) || getSetting('public_server_host');
      const pInfo = await queryServerPing(s.port || 25565, adminDpHost, customHost || s.ip);
      if (pInfo && pInfo.success) {
        s.online = pInfo.online;
        s.max_online = pInfo.max;
        s.maxOnline = pInfo.max;
        try {
          db.prepare('UPDATE servers SET online = ?, max_online = ? WHERE id = ?').run(s.online, s.max_online, s.id);
        } catch(e) {}
      } else {
        s.maxOnline = s.max_online || 20;
      }
    }
  }
  const totalPlayersOnline = servers.reduce((acc, s) => acc + (s.online || 0), 0);
  res.json({ success: true, totalPlayersOnline, servers });
});

adminApp.post('/api/admin/config', requireAdminAuth, async (req, res) => {
  const { discopanel_url, discopanel_token } = req.body;
  if (discopanel_url) setSetting('discopanel_url', discopanel_url);
  if (discopanel_token) setSetting('discopanel_token', discopanel_token);
  try {
    await syncWithDiscoPanelAPI();
  } catch (e) {}
  res.json({ success: true });
});

// Set public host / domain for a server
adminApp.post('/api/admin/servers/:id/public-host', requireAdminAuth, (req, res) => {
  const serverId = req.params.id;
  const { host } = req.body;
  const cleanHost = (host || '').trim();
  setSetting('public_server_host_' + serverId, cleanHost);
  if (cleanHost) {
    const parsed = parseHostAndPort(cleanHost);
    db.prepare('UPDATE servers SET ip = ?, port = ? WHERE id = ?').run(parsed.host, parsed.port, serverId);
  } else {
    // Revert to DiscoPanel IP and default port
    const dpUrl = getSetting('discopanel_url', 'http://192.168.10.127:8080');
    let fallbackIp = '192.168.10.127';
    try { fallbackIp = new URL(dpUrl).hostname; } catch(e) {}
    db.prepare('UPDATE servers SET ip = ?, port = 25565 WHERE id = ?').run(fallbackIp, serverId);
  }
  res.json({ success: true, host: cleanHost });
});

// Toggle DiscoPanel mods sync for a server
adminApp.post('/api/admin/servers/:id/toggle-sync', requireAdminAuth, (req, res) => {
  const serverId = req.params.id;
  const { enabled } = req.body;
  setSetting('sync_mods_' + serverId, enabled ? 'true' : 'false');
  res.json({ success: true, enabled: !!enabled });
});

// Toggle individual mod enabled/disabled
adminApp.post('/api/admin/servers/:id/toggle-mod', requireAdminAuth, (req, res) => {
  const serverId = req.params.id;
  const { filename, enabled } = req.body;
  if (!filename) return res.status(400).json({ success: false, error: 'Filename not specified' });

  const safeFilename = path.basename(filename);
  const disabledModsPath = path.join(SERVERS_DIR, serverId, 'disabled_mods.json');
  let disabledMods = [];
  try {
    if (fs.existsSync(disabledModsPath)) {
      disabledMods = JSON.parse(fs.readFileSync(disabledModsPath, 'utf8'));
    }
  } catch (e) {}

  if (enabled) {
    disabledMods = disabledMods.filter(f => f !== safeFilename);
  } else {
    if (!disabledMods.includes(safeFilename)) disabledMods.push(safeFilename);
  }

  fs.writeFileSync(disabledModsPath, JSON.stringify(disabledMods, null, 2));
  res.json({ success: true, filename: safeFilename, enabled: !!enabled });
});

// Upload client-side mods
adminApp.post('/api/admin/servers/:id/upload-mod', requireAdminAuth, modUpload.array('mods', 50), (req, res) => {
  const serverId = req.params.id;
  const files = req.files || [];
  if (files.length === 0) return res.status(400).json({ success: false, error: 'No files selected' });

  // Record into client_mods.json
  const clientModsPath = path.join(SERVERS_DIR, serverId, 'client_mods.json');
  let clientMods = [];
  try {
    if (fs.existsSync(clientModsPath)) {
      clientMods = JSON.parse(fs.readFileSync(clientModsPath, 'utf8'));
    }
  } catch (e) {}

  const addedNames = files.map(f => f.filename);
  clientMods = Array.from(new Set([...clientMods, ...addedNames]));
  fs.writeFileSync(clientModsPath, JSON.stringify(clientMods, null, 2));

  // Update total_mods in DB
  const count = clientMods.length;
  db.prepare('UPDATE servers SET total_mods = ? WHERE id = ?').run(count, serverId);

  res.json({ success: true, count: files.length, files: addedNames });
});

// Delete mod
adminApp.post('/api/admin/servers/:id/delete-mod', requireAdminAuth, (req, res) => {
  const serverId = req.params.id;
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ success: false, error: 'Filename not specified' });

  const safeFilename = path.basename(filename);

  // If this mod is from DiscoPanel, keep the server jar on disk and just unimport from client_mods.json
  const dpModsPath = path.join(SERVERS_DIR, serverId, 'dp_mods.json');
  let dpMods = [];
  try {
    if (fs.existsSync(dpModsPath)) {
      dpMods = JSON.parse(fs.readFileSync(dpModsPath, 'utf8'));
    }
  } catch (e) {}

  if (!dpMods.includes(safeFilename)) {
    const targetPath = path.join(SERVERS_DIR, serverId, 'mods', safeFilename);
    if (fs.existsSync(targetPath)) {
      try { fs.unlinkSync(targetPath); } catch(e) {}
    }
  }

  // Remove from client_mods.json
  const clientModsPath = path.join(SERVERS_DIR, serverId, 'client_mods.json');
  let clientMods = [];
  try {
    if (fs.existsSync(clientModsPath)) {
      clientMods = JSON.parse(fs.readFileSync(clientModsPath, 'utf8'));
      clientMods = clientMods.filter(n => n !== safeFilename);
      fs.writeFileSync(clientModsPath, JSON.stringify(clientMods, null, 2));
    }
  } catch (e) {}

  // Update total_mods in DB
  const count = clientMods.length;
  db.prepare('UPDATE servers SET total_mods = ? WHERE id = ?').run(count, serverId);

  res.json({ success: true });
});

// Import mod from DiscoPanel into client mods
adminApp.post('/api/admin/servers/:id/import-dp-mod', requireAdminAuth, (req, res) => {
  const serverId = req.params.id;
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ success: false, error: 'Filename not specified' });

  const safeFilename = path.basename(filename);
  const clientModsPath = path.join(SERVERS_DIR, serverId, 'client_mods.json');
  let clientMods = [];
  try {
    if (fs.existsSync(clientModsPath)) {
      clientMods = JSON.parse(fs.readFileSync(clientModsPath, 'utf8'));
    }
  } catch (e) {}

  if (!clientMods.includes(safeFilename)) {
    clientMods.push(safeFilename);
    fs.writeFileSync(clientModsPath, JSON.stringify(clientMods, null, 2));
  }

  // Update total_mods in DB
  db.prepare('UPDATE servers SET total_mods = ? WHERE id = ?').run(clientMods.length, serverId);

  res.json({ success: true, filename: safeFilename });
});

// Unimport mod from client mods (removes from client_mods.json, leaves jar on server)
adminApp.post('/api/admin/servers/:id/unimport-dp-mod', requireAdminAuth, (req, res) => {
  const serverId = req.params.id;
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ success: false, error: 'Filename not specified' });

  const safeFilename = path.basename(filename);
  const clientModsPath = path.join(SERVERS_DIR, serverId, 'client_mods.json');
  let clientMods = [];
  try {
    if (fs.existsSync(clientModsPath)) {
      clientMods = JSON.parse(fs.readFileSync(clientModsPath, 'utf8'));
      clientMods = clientMods.filter(n => n !== safeFilename);
      fs.writeFileSync(clientModsPath, JSON.stringify(clientMods, null, 2));
    }
  } catch (e) {}

  // Update total_mods in DB
  const count = clientMods.length;
  db.prepare('UPDATE servers SET total_mods = ? WHERE id = ?').run(count, serverId);

  res.json({ success: true, filename: safeFilename });
});

// Upload shaders (.zip)
adminApp.post('/api/admin/servers/:id/upload-shader', requireAdminAuth, shaderUpload.array('shaders', 20), (req, res) => {
  const files = req.files || [];
  if (files.length === 0) return res.status(400).json({ success: false, error: 'No files selected' });
  res.json({ success: true, count: files.length, files: files.map(f => f.filename) });
});

// Delete shader (.zip)
adminApp.post('/api/admin/servers/:id/delete-shader', requireAdminAuth, (req, res) => {
  const serverId = req.params.id;
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ success: false, error: 'Filename not specified' });

  const safeFilename = path.basename(filename);
  const targetPath = path.join(SERVERS_DIR, serverId, 'shaderpacks', safeFilename);
  if (fs.existsSync(targetPath)) {
    fs.unlinkSync(targetPath);
  }
  res.json({ success: true });
});

// Upload resourcepacks (.zip)
adminApp.post('/api/admin/servers/:id/upload-resourcepack', requireAdminAuth, resourcepackUpload.array('resourcepacks', 20), (req, res) => {
  const files = req.files || [];
  if (files.length === 0) return res.status(400).json({ success: false, error: 'No files selected' });
  res.json({ success: true, count: files.length, files: files.map(f => f.filename) });
});

// Delete resourcepack (.zip)
adminApp.post('/api/admin/servers/:id/delete-resourcepack', requireAdminAuth, (req, res) => {
  const serverId = req.params.id;
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ success: false, error: 'Filename not specified' });

  const safeFilename = path.basename(filename);
  const targetPath = path.join(SERVERS_DIR, serverId, 'resourcepacks', safeFilename);
  if (fs.existsSync(targetPath)) {
    fs.unlinkSync(targetPath);
  }
  res.json({ success: true });
});

adminApp.post('/api/admin/sync-api', requireAdminAuth, async (req, res) => {
  try {
    const result = await syncWithDiscoPanelAPI();
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// =========================================================================
// FILE MANAGER API ENDPOINTS
// =========================================================================

adminApp.get('/api/admin/fs/servers', requireAdminAuth, (req, res) => {
  try {
    const dbServers = db.prepare('SELECT id, name, version, ip, port FROM servers').all();
    const dbMap = new Map(dbServers.map(s => [s.id, s]));

    if (!fs.existsSync(SERVERS_DIR)) {
      return res.json({ success: true, servers: [] });
    }

    const dirEntries = fs.readdirSync(SERVERS_DIR, { withFileTypes: true });
    const result = [];

    for (const ent of dirEntries) {
      if (!ent.isDirectory() || ent.name.startsWith('.')) continue;
      const srvId = ent.name;
      const srvDir = path.join(SERVERS_DIR, srvId);
      const isDb = dbMap.has(srvId);
      const dbInfo = dbMap.get(srvId);

      const modsDir = path.join(srvDir, 'mods');
      const shadersDir = path.join(srvDir, 'shaderpacks');
      const rpDir = path.join(srvDir, 'resourcepacks');
      const clientModsFile = path.join(srvDir, 'client_mods.json');

      let modsCount = 0;
      let shadersCount = 0;
      let rpCount = 0;
      let hasClientMods = false;

      try {
        if (fs.existsSync(modsDir)) {
          modsCount = fs.readdirSync(modsDir).filter(f => f.endsWith('.jar')).length;
        }
      } catch (e) {}

      try {
        if (fs.existsSync(shadersDir)) {
          shadersCount = fs.readdirSync(shadersDir).filter(f => !f.startsWith('.')).length;
        }
      } catch (e) {}

      try {
        if (fs.existsSync(rpDir)) {
          rpCount = fs.readdirSync(rpDir).filter(f => !f.startsWith('.')).length;
        }
      } catch (e) {}

      try {
        if (fs.existsSync(clientModsFile)) {
          hasClientMods = true;
        }
      } catch (e) {}

      result.push({
        id: srvId,
        name: dbInfo ? dbInfo.name : srvId,
        isActive: isDb,
        gameVersion: dbInfo ? dbInfo.version : 'Локальный',
        modsCount,
        shadersCount,
        rpCount,
        hasClientMods
      });
    }

    result.sort((a, b) => {
      if (a.isActive && !b.isActive) return -1;
      if (!a.isActive && b.isActive) return 1;
      return a.name.localeCompare(b.name);
    });

    res.json({ success: true, servers: result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

adminApp.get('/api/admin/fs/list', requireAdminAuth, (req, res) => {
  try {
    const { serverId, subpath = '' } = req.query;
    const { targetPath, normalizedSubpath } = resolveSafePath(serverId, subpath);

    if (!fs.existsSync(targetPath)) {
      return res.status(404).json({ success: false, error: 'Папка не найдена' });
    }
    const stat = fs.statSync(targetPath);
    if (!stat.isDirectory()) {
      return res.status(400).json({ success: false, error: 'Указанный путь не является папкой' });
    }

    const dirents = fs.readdirSync(targetPath, { withFileTypes: true });
    const items = [];

    for (const d of dirents) {
      if (d.name.startsWith('.') && d.name !== '.env') continue;
      const full = path.join(targetPath, d.name);
      try {
        const s = fs.statSync(full);
        items.push({
          name: d.name,
          isDir: d.isDirectory(),
          size: d.isDirectory() ? 0 : s.size,
          mtime: s.mtimeMs,
          ext: d.isDirectory() ? '' : path.extname(d.name).toLowerCase()
        });
      } catch (e) {}
    }

    items.sort((a, b) => {
      if (a.isDir && !b.isDir) return -1;
      if (!a.isDir && b.isDir) return 1;
      return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
    });

    res.json({
      success: true,
      serverId,
      currentPath: normalizedSubpath.replace(/\\/g, '/'),
      items
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

adminApp.get('/api/admin/fs/download', requireAdminAuth, (req, res) => {
  try {
    const { serverId, filepath } = req.query;
    if (!filepath) return res.status(400).json({ success: false, error: 'Не указан файл' });
    const { targetPath } = resolveSafePath(serverId, filepath);

    if (!fs.existsSync(targetPath)) {
      return res.status(404).json({ success: false, error: 'Файл не найден' });
    }
    const stat = fs.statSync(targetPath);
    if (stat.isDirectory()) {
      return res.status(400).json({ success: false, error: 'Путь ведет к папке, используйте скачивание ZIP' });
    }

    res.download(targetPath, path.basename(targetPath));
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

adminApp.get('/api/admin/fs/download-zip', requireAdminAuth, (req, res) => {
  try {
    const { serverId, subpath = '' } = req.query;
    const { targetPath, normalizedSubpath } = resolveSafePath(serverId, subpath);

    if (!fs.existsSync(targetPath)) {
      return res.status(404).json({ success: false, error: 'Папка не найдена' });
    }
    const stat = fs.statSync(targetPath);
    if (!stat.isDirectory()) {
      return res.status(400).json({ success: false, error: 'Путь не является директорией' });
    }

    const zipBaseName = normalizedSubpath ? path.basename(normalizedSubpath) : serverId;
    const zipName = `${zipBaseName}.zip`;
    const tempZip = path.join(os.tmpdir(), `fs_export_${Date.now()}_${Math.random().toString(36).slice(2)}.zip`);

    execFile('zip', ['-r', tempZip, '.'], { cwd: targetPath }, (err, stdout, stderr) => {
      if (err && !fs.existsSync(tempZip)) {
        return res.status(500).json({ success: false, error: 'Ошибка создания ZIP архива: ' + (stderr || err.message) });
      }
      res.download(tempZip, zipName, () => {
        try { if (fs.existsSync(tempZip)) fs.unlinkSync(tempZip); } catch (e) {}
      });
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

adminApp.post('/api/admin/fs/upload', requireAdminAuth, (req, res) => {
  fmUpload.array('files', 100)(req, res, (err) => {
    if (err) {
      return res.status(400).json({ success: false, error: err.message });
    }
    const files = req.files || [];
    res.json({ success: true, count: files.length });
  });
});

adminApp.post('/api/admin/fs/mkdir', requireAdminAuth, (req, res) => {
  try {
    const { serverId, subpath = '', dirName } = req.body;
    if (!dirName || typeof dirName !== 'string') {
      return res.status(400).json({ success: false, error: 'Не указано имя папки' });
    }
    const cleanDirName = path.basename(dirName).replace(/[^a-zA-Z0-9_\-\. ]/g, '_');
    if (!cleanDirName) {
      return res.status(400).json({ success: false, error: 'Некорректное имя папки' });
    }

    const { targetPath } = resolveSafePath(serverId, subpath);
    const newDirPath = path.join(targetPath, cleanDirName);
    if (fs.existsSync(newDirPath)) {
      return res.status(400).json({ success: false, error: 'Папка уже существует' });
    }

    fs.mkdirSync(newDirPath, { recursive: true });
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

adminApp.post('/api/admin/fs/delete', requireAdminAuth, (req, res) => {
  try {
    const { serverId, filepath } = req.body;
    if (!filepath || filepath === '/' || filepath === '.') {
      return res.status(400).json({ success: false, error: 'Нельзя удалить корневую папку напрямую' });
    }
    const { serverRoot, targetPath } = resolveSafePath(serverId, filepath);
    if (targetPath === serverRoot) {
      return res.status(400).json({ success: false, error: 'Удаление всего сервера выполняется через отдельную кнопку' });
    }

    if (!fs.existsSync(targetPath)) {
      return res.status(404).json({ success: false, error: 'Файл или папка не найдены' });
    }

    fs.rmSync(targetPath, { recursive: true, force: true });
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

adminApp.post('/api/admin/fs/delete-server', requireAdminAuth, (req, res) => {
  try {
    const { serverId, confirmText } = req.body;
    if (!serverId) return res.status(400).json({ success: false, error: 'Не указан serverId' });
    if (confirmText !== serverId) {
      return res.status(400).json({ success: false, error: 'Подтверждение не совпадает' });
    }

    const active = db.prepare('SELECT id FROM servers WHERE id = ?').get(serverId);
    if (active) {
      return res.status(400).json({ success: false, error: 'Нельзя удалить активный синхронизируемый сервер' });
    }

    const { serverRoot } = resolveSafePath(serverId, '');
    if (fs.existsSync(serverRoot)) {
      fs.rmSync(serverRoot, { recursive: true, force: true });
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

adminApp.post('/api/admin/fs/migrate-archive', requireAdminAuth, (req, res) => {
  try {
    const { sourceServerId, targetServerId, options = {} } = req.body;
    if (!sourceServerId || !targetServerId) {
      return res.status(400).json({ success: false, error: 'Укажите исходный и целевой серверы' });
    }
    const { serverRoot: sourceDir } = resolveSafePath(sourceServerId, '');
    const { serverRoot: targetDir } = resolveSafePath(targetServerId, '');

    if (!fs.existsSync(sourceDir)) {
      return res.status(404).json({ success: false, error: 'Папка исходного сервера не найдена' });
    }
    if (!fs.existsSync(targetDir)) {
      return res.status(404).json({ success: false, error: 'Папка целевого сервера не найдена' });
    }

    let copiedShaders = 0;
    let copiedResourcepacks = 0;
    let copiedMods = 0;

    // 1. Shaders
    if (options.copyShaders) {
      const srcShaders = path.join(sourceDir, 'shaderpacks');
      const dstShaders = path.join(targetDir, 'shaderpacks');
      if (fs.existsSync(srcShaders)) {
        if (!fs.existsSync(dstShaders)) fs.mkdirSync(dstShaders, { recursive: true });
        const files = fs.readdirSync(srcShaders);
        for (const f of files) {
          const sFile = path.join(srcShaders, f);
          if (fs.statSync(sFile).isFile()) {
            fs.copyFileSync(sFile, path.join(dstShaders, f));
            copiedShaders++;
          }
        }
      }
    }

    // 2. Resource packs
    if (options.copyResourcepacks) {
      const srcRp = path.join(sourceDir, 'resourcepacks');
      const dstRp = path.join(targetDir, 'resourcepacks');
      if (fs.existsSync(srcRp)) {
        if (!fs.existsSync(dstRp)) fs.mkdirSync(dstRp, { recursive: true });
        const files = fs.readdirSync(srcRp);
        for (const f of files) {
          const sFile = path.join(srcRp, f);
          if (fs.statSync(sFile).isFile()) {
            fs.copyFileSync(sFile, path.join(dstRp, f));
            copiedResourcepacks++;
          }
        }
      }
    }

    // 3. Client Mods & client_mods.json
    if (options.copyClientMods) {
      const srcClientJson = path.join(sourceDir, 'client_mods.json');
      const dstClientJson = path.join(targetDir, 'client_mods.json');
      const srcMods = path.join(sourceDir, 'mods');
      const dstMods = path.join(targetDir, 'mods');
      if (fs.existsSync(srcClientJson) && fs.existsSync(srcMods)) {
        if (!fs.existsSync(dstMods)) fs.mkdirSync(dstMods, { recursive: true });
        let srcList = [];
        try { srcList = JSON.parse(fs.readFileSync(srcClientJson, 'utf8')); } catch (e) {}
        let dstList = [];
        try { if (fs.existsSync(dstClientJson)) dstList = JSON.parse(fs.readFileSync(dstClientJson, 'utf8')); } catch (e) {}

        const dstSet = new Set(dstList);
        for (const modName of srcList) {
          const sMod = path.join(srcMods, modName);
          if (fs.existsSync(sMod) && fs.statSync(sMod).isFile()) {
            fs.copyFileSync(sMod, path.join(dstMods, modName));
            dstSet.add(modName);
            copiedMods++;
          }
        }
        fs.writeFileSync(dstClientJson, JSON.stringify(Array.from(dstSet), null, 2), 'utf8');
      }
    }

    // 4. All Mods
    if (options.copyAllMods) {
      const srcMods = path.join(sourceDir, 'mods');
      const dstMods = path.join(targetDir, 'mods');
      if (fs.existsSync(srcMods)) {
        if (!fs.existsSync(dstMods)) fs.mkdirSync(dstMods, { recursive: true });
        const files = fs.readdirSync(srcMods);
        for (const f of files) {
          if (f.endsWith('.jar')) {
            const sFile = path.join(srcMods, f);
            if (fs.statSync(sFile).isFile()) {
              fs.copyFileSync(sFile, path.join(dstMods, f));
              copiedMods++;
            }
          }
        }
      }
    }

    // Update target server total_mods in DB
    try {
      const dstMods = path.join(targetDir, 'mods');
      if (fs.existsSync(dstMods)) {
        const count = fs.readdirSync(dstMods).filter(f => f.endsWith('.jar')).length;
        db.prepare('UPDATE servers SET total_mods = ? WHERE id = ?').run(count, targetServerId);
      }
    } catch (e) {}

    res.json({
      success: true,
      copiedShaders,
      copiedResourcepacks,
      copiedMods,
      message: `Перенесено: ${copiedShaders} шейдеров, ${copiedResourcepacks} ресурспаков, ${copiedMods} модов`
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// =========================================================================
// 4. START BOTH SERVERS
// =========================================================================

// Start Launcher API on port 6500
launcherApp.listen(LAUNCHER_PORT, '0.0.0.0', () => {
  console.log(`[Launcher API] Running on http://0.0.0.0:${LAUNCHER_PORT}`);
  // Initial sync and auto-sync every 30 seconds
  syncWithDiscoPanelAPI().catch(err => console.warn('Initial sync notice:', err.message));
  setInterval(() => {
    syncWithDiscoPanelAPI().catch(() => {});
  }, 30000);
});

// Start Admin Web Panel on port 5000
adminApp.listen(ADMIN_PORT, '0.0.0.0', () => {
  console.log(`[Admin Panel] Running on http://0.0.0.0:${ADMIN_PORT}`);
});
