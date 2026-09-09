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

// Config & Ports
const ADMIN_PORT = process.env.ADMIN_PORT || 5000;
const LAUNCHER_PORT = process.env.LAUNCHER_PORT || 6500;
const JWT_SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(32).toString('hex');

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

// Initial DiscoPanel config defaults
if (!getSetting('discopanel_url')) {
  setSetting('discopanel_url', '');
}
if (!getSetting('discopanel_token')) {
  setSetting('discopanel_token', '');
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
  const token = cookies.admin_token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);

  if (!token) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ success: false, error: 'Требуется авторизация' });
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
    return res.status(401).json({ success: false, error: 'Сессия истекла' });
  }
  return res.redirect('/login');
}

// Launcher Player Auth Middleware
function authenticatePlayerToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Требуется токен авторизации' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Недействительный токен' });
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
var MC_PING_TTL = 25000;

function getCachedMcOnline(ip, port) {
  var key = ip + ':' + port;
  var now = Date.now();
  if (_mcPingCache[key] && now - _mcPingCache[key].ts < MC_PING_TTL) {
    return Promise.resolve(_mcPingCache[key].online);
  }
  return mcPing(ip, port).then(function(r) {
    var online = r ? r.online : 0;
    _mcPingCache[key] = { online: online, ts: Date.now() };
    console.log('[MC Ping] ' + ip + ':' + port + ' -> ' + online + ' players online');
    return online;
  }).catch(function() { return 0; });
}


async function syncWithDiscoPanelAPI() {
  const dpUrl = getSetting('discopanel_url', 'http://192.168.10.127:8080');
  const dpToken = getSetting('discopanel_token');

  if (!dpToken) throw new Error('API токен DiscoPanel не настроен!');

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
    throw new Error(`Ошибка DiscoPanel API (${serversRes.status}): ${await serversRes.text()}`);
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

        for (const m of mods) {
          if (!m.enabled) continue;
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
      }
    } else {
      console.log(`[Sync] DiscoPanel mods sync is disabled for server ${s.name}`);
    }

    // Count all local mods in modsDir
    const modCount = fs.existsSync(modsDir) ? fs.readdirSync(modsDir).filter(f => f.endsWith('.jar')).length : 0;

    // 3. Update server in SQLite
    const modLoaderClean = (s.modLoader || '').replace('MOD_LOADER_', '').toLowerCase() || 'vanilla';
    const isRunning = s.status === 'SERVER_STATUS_RUNNING';
    let serverHost = '127.0.0.1';
    try { serverHost = new URL(dpUrl).hostname; } catch(e) {}
    const customHost = getSetting('public_server_host_' + srvId) || getSetting('public_server_host');
    if (customHost && customHost.trim()) {
      serverHost = customHost.trim();
    }

    // Ping the real Minecraft server for accurate player count
    var realOnline = await getCachedMcOnline(serverHost, s.port || 25565);

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
      'Сервер из DiscoPanel',
      s.mcVersion || '1.21.5',
      modLoaderClean,
      serverHost,
      s.port || 25565,
      realOnline,
      s.maxPlayers || 100,
      isRunning ? 'online' : 'offline',
      s.description || 'Игровой сервер DiscoPanel',
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
    if (!username || !password) return res.status(400).json({ error: 'Логин и пароль обязательны' });
    if (username.length < 3 || username.length > 16) return res.status(400).json({ error: 'Длина ника от 3 до 16 символов' });

    const existing = db.prepare('SELECT id FROM users WHERE lower(username) = lower(?)').get(username);
    if (existing) return res.status(409).json({ error: 'Пользователь с таким ником уже существует' });

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
    if (!username || !password) return res.status(400).json({ error: 'Введите логин и пароль' });

    const user = db.prepare('SELECT * FROM users WHERE lower(username) = lower(?)').get(username);
    if (!user) return res.status(401).json({ error: 'Неверный логин или пароль' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Неверный логин или пароль' });

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
launcherApp.get('/api/servers', (req, res) => {
  const servers = db.prepare('SELECT * FROM servers').all();
  servers.forEach(s => {
    s.maxOnline = s.max_online || 100;
    s.manifestUrl = s.manifest_url || `/api/servers/${s.id}/manifest`;
    s.totalMods = 0;
    const modsDir = path.join(SERVERS_DIR, s.id, 'mods');
    if (fs.existsSync(modsDir)) {
      s.totalMods = fs.readdirSync(modsDir).filter(f => f.endsWith('.jar')).length;
      s.total_mods = s.totalMods;
    }
    const customHost = getSetting('public_server_host_' + s.id) || getSetting('public_server_host');
    if (customHost && customHost.trim()) {
      s.ip = customHost.trim();
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
      const relPath = path.posix.join(relativePrefix, ent.name);
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

  const html = `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Вход в панель управления - DiscoLauncher</title>
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
        <h1 class="text-2xl font-black text-white tracking-wide">Панель управления</h1>
        <p class="text-xs text-slate-400 mt-1">Авторизуйтесь для доступа к управлению серверами</p>
      </div>

      <form id="loginForm" onsubmit="handleLogin(event)" class="space-y-4 relative">
        <div id="errorBox" class="hidden p-3 rounded-xl bg-red-950/50 border border-red-800/60 text-xs text-red-300 flex items-center gap-2">
          <i class="fa-solid fa-triangle-exclamation text-red-400"></i>
          <span id="errorMsg">Неверный логин или пароль</span>
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-300 mb-1.5">Логин</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <i class="fa-solid fa-user text-xs"></i>
            </span>
            <input type="text" id="username" required autocomplete="username" value="varringard" placeholder="varringard"
              class="w-full pl-10 pr-4 py-2.5 bg-slate-900/90 border border-slate-700/80 rounded-xl text-xs text-white placeholder-slate-500 focus:border-indigo-500 focus:outline-none transition-colors">
          </div>
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-300 mb-1.5">Пароль</label>
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
          <span>Войти</span>
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
          window.location.href = '/admin';
        } else {
          errText.textContent = data.error || 'Неверный логин или пароль';
          errBox.classList.remove('hidden');
        }
      } catch (err) {
        errText.textContent = 'Ошибка сети: ' + err.message;
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
    const token = jwt.sign({ role: 'admin', user: adminCreds.username }, JWT_SECRET, { expiresIn: '7d' });
    res.setHeader('Set-Cookie', `admin_token=${token}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax`);
    return res.json({ success: true, token });
  }
  return res.status(401).json({ success: false, error: 'Неверный логин или пароль' });
});

adminApp.post('/api/admin/change-credentials', requireAdminAuth, (req, res) => {
  const { currentPassword, newUsername, newPassword } = req.body;
  if (!newUsername || !newUsername.trim()) {
    return res.status(400).json({ success: false, error: 'Логин не может быть пустым' });
  }
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ success: false, error: 'Новый пароль должен быть не менее 4 символов' });
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
    return res.status(400).json({ success: false, error: 'Текущий пароль указан неверно' });
  }

  const cleanUser = newUsername.trim();
  const newHash = bcrypt.hashSync(newPassword, 10);
  setSetting('admin_username', cleanUser);
  setSetting('admin_password_hash', newHash);
  setSetting('admin_password', ''); // clear plain

  const token = jwt.sign({ role: 'admin', user: cleanUser }, JWT_SECRET, { expiresIn: '7d' });
  res.setHeader('Set-Cookie', `admin_token=${token}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax`);

  return res.json({ success: true, message: 'Данные администратора успешно изменены' });
});

adminApp.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'admin_token=; HttpOnly; Path=/; Max-Age=0');
  res.json({ success: true });
});

// Admin Dashboard Route
adminApp.get('/admin', requireAdminAuth, (req, res) => {
  const servers = db.prepare('SELECT * FROM servers').all();
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

    s.modsList = allMods.map(m => {
      let sizeMb = '0.0';
      try {
        const stat = fs.statSync(path.join(modsDir, m));
        sizeMb = (stat.size / (1024 * 1024)).toFixed(1);
      } catch (e) {}
      return {
        name: m,
        isClient: clientModsSet.has(m),
        isEnabled: !disabledModsSet.has(m),
        sizeMb
      };
    });
    s.totalMods = allMods.length;
    s.enabledModsCount = s.modsList.filter(m => m.isEnabled).length;
    s.disabledModsCount = s.totalMods - s.enabledModsCount;
    s.isModsSyncEnabled = getSetting('sync_mods_' + s.id, 'true') !== 'false';
    const customHost = getSetting('public_server_host_' + s.id) || getSetting('public_server_host');
    if (customHost && customHost.trim()) {
      s.ip = customHost.trim();
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
<html lang="ru" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DiscoPanel - Серверы и Модпаки</title>
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
            <button onclick="openCredentialsModal()" title="Сменить логин или пароль" class="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors">
              <i class="fa-solid fa-key text-xs"></i>
            </button>
            <button onclick="logoutAdmin()" title="Выйти" class="p-1.5 rounded-lg hover:bg-red-950/40 text-slate-400 hover:text-red-400 transition-colors">
              <i class="fa-solid fa-right-from-bracket text-xs"></i>
            </button>
          </div>
        </div>

        <div class="flex items-center justify-between px-2 pt-3 text-[10px] text-slate-600 font-mono">
          <span>v1.2.3</span>
          <span class="flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> Proxmox LXC 107</span>
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
            <p class="text-xs text-slate-400">Нажмите на сервер для управления модами, шейдерами и настройками</p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <button onclick="triggerSyncNow()" class="px-4 py-2 rounded-xl bg-white hover:bg-slate-200 text-black text-xs font-bold flex items-center gap-2 transition-all shadow-md">
            <i class="fa-solid fa-arrows-rotate text-xs"></i>
            <span>Синхронизировать</span>
          </button>
        </div>
      </div>

      <!-- Search & Status Bar -->
      <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
        <div class="relative flex-1 max-w-md">
          <i class="fa-solid fa-magnifying-glass absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 text-xs"></i>
          <input type="text" id="serverSearchInput" oninput="filterServers(this.value)" placeholder="Search by name, version, or mod loader.." class="w-full bg-[#11131a] border border-[#1d202c] rounded-xl pl-9 pr-4 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500/60 font-sans transition-all">
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
                  <p class="text-xs text-slate-400 mt-0.5">${s.description || 'Minecraft сервер без описания'}</p>
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
                  <span>Моды и файлы</span>
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
                  <span class="text-cyan-400 font-bold">${s.enabledModsCount}</span> <span class="text-slate-500 text-xs">/ ${s.totalMods} вкл.</span>
                </div>
              </div>

              <div class="p-3 rounded-xl bg-[#0b0c11] border border-[#171924] hover:border-slate-700 transition-colors">
                <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
                  <i class="fa-solid fa-users text-emerald-400"></i> PLAYERS
                </div>
                <div class="text-sm font-bold font-mono mt-1">
                  <span class="text-emerald-400 font-bold">${s.online || 0}</span> <span class="text-slate-500">/ ${s.maxOnline}</span>
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
                  <span>Моды</span>
                  <span class="px-1.5 py-0.2 rounded bg-indigo-500/40 text-[10px] font-mono">${s.totalMods}</span>
                </button>
                <button onclick="switchServerTab('${s.id}', 'shaders')" id="srvTabBtn_${s.id}_shaders" class="px-4 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white bg-[#12141c] hover:bg-[#1a1d28] transition-all flex items-center gap-1.5">
                  <i class="fa-solid fa-sun text-amber-400"></i>
                  <span>Шейдеры</span>
                  <span class="text-[10px] text-slate-500 font-mono">${s.shadersList.length}</span>
                </button>
                <button onclick="switchServerTab('${s.id}', 'resourcepacks')" id="srvTabBtn_${s.id}_resourcepacks" class="px-4 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white bg-[#12141c] hover:bg-[#1a1d28] transition-all flex items-center gap-1.5">
                  <i class="fa-solid fa-palette text-emerald-400"></i>
                  <span>Ресурспаки</span>
                  <span class="text-[10px] text-slate-500 font-mono">${s.resourcepacksList.length}</span>
                </button>
                <button onclick="switchServerTab('${s.id}', 'host')" id="srvTabBtn_${s.id}_host" class="px-4 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white bg-[#12141c] hover:bg-[#1a1d28] transition-all flex items-center gap-1.5">
                  <i class="fa-solid fa-globe text-cyan-400"></i>
                  <span>Адрес сервера</span>
                </button>
              </div>

              <!-- ================= TAB: MODS ================= -->
              <div id="srvTab_${s.id}_mods" class="space-y-4">
                
                <!-- Mods Controls Bar -->
                <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-[#0b0c11] border border-[#1a1d2b] p-3.5 rounded-xl">
                  <div class="flex items-center gap-3">
                    <!-- Quick Mod Search -->
                    <div class="relative w-full sm:w-64">
                      <i class="fa-solid fa-magnifying-glass absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-xs"></i>
                      <input type="text" oninput="filterModRows('${s.id}', this.value)" placeholder="Поиск мода..." class="w-full bg-[#12141c] border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500 font-sans">
                    </div>

                    <!-- DiscoPanel Sync Toggle -->
                    <label class="flex items-center gap-2 cursor-pointer text-xs text-slate-300 font-medium select-none">
                      <input type="checkbox" ${s.isModsSyncEnabled ? 'checked' : ''} onchange="toggleSync('${s.id}', this.checked)" class="w-4 h-4 accent-indigo-600 rounded">
                      <span class="hidden md:inline">Синхронизация DiscoPanel</span>
                    </label>
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

                <!-- Mods Table / List -->
                ${s.modsList.length === 0 ? `
                  <div class="p-8 text-center bg-[#0b0c11] border border-dashed border-[#1a1d2b] rounded-xl text-xs text-slate-500">
                    В папке сервера пока нет модов (.jar). Нажмите «Загрузить клиентский .jar» или включите синхронизацию с DiscoPanel.
                  </div>
                ` : `
                  <div class="bg-[#0b0c11] border border-[#1a1d2b] rounded-xl overflow-hidden">
                    <div class="max-h-[380px] overflow-y-auto divide-y divide-[#151724]">
                      ${s.modsList.map(m => `
                        <div id="modRow_${s.id}_${encodeURIComponent(m.name)}" data-name="${m.name.toLowerCase()}" class="flex items-center justify-between p-3 hover:bg-[#121520] transition-colors gap-3">
                          
                          <!-- Switch + Name -->
                          <div class="flex items-center gap-3 min-w-0">
                            <!-- Toggle Switch -->
                            <label class="relative inline-flex items-center cursor-pointer shrink-0">
                              <input type="checkbox" ${m.isEnabled ? 'checked' : ''} onchange="toggleMod('${s.id}', '${m.name}', this.checked)" class="sr-only peer">
                              <div class="w-8 h-4 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-3 after:w-3.5 after:transition-all peer-checked:bg-emerald-500"></div>
                            </label>

                            <!-- Mod icon & Filename -->
                            <div class="min-w-0">
                              <div class="text-xs font-medium font-mono text-slate-200 truncate ${!m.isEnabled ? 'line-through text-slate-500' : ''}" id="modTitle_${s.id}_${encodeURIComponent(m.name)}">
                                ${m.name}
                              </div>
                              <div class="text-[10px] text-slate-500 font-sans mt-0.5">
                                ${m.sizeMb} MB &bull; ${m.isEnabled ? '<span class="text-emerald-400 font-semibold">Включен</span>' : '<span class="text-slate-500">Отключен (не качается игрокам)</span>'}
                              </div>
                            </div>
                          </div>

                          <!-- Badges & Delete -->
                          <div class="flex items-center gap-2 shrink-0">
                            ${m.isClient ? `
                              <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">Клиентский</span>
                              <button onclick="deleteMod('${s.id}', '${m.name}')" title="Удалить мод" class="p-1 rounded hover:bg-red-950/40 text-slate-500 hover:text-red-400 transition-colors">
                                <i class="fa-solid fa-trash-can text-xs"></i>
                              </button>
                            ` : `
                              <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20">Серверный (DiscoPanel)</span>
                            `}
                          </div>

                        </div>
                      `).join('')}
                    </div>
                  </div>
                `}

              </div>

              <!-- ================= TAB: SHADERS ================= -->
              <div id="srvTab_${s.id}_shaders" class="hidden space-y-4">
                <div class="flex items-center justify-between bg-[#0b0c11] border border-[#1a1d2b] p-3.5 rounded-xl">
                  <div>
                    <div class="text-xs font-bold text-amber-400 flex items-center gap-2">
                      <i class="fa-solid fa-sun"></i>
                      <span>Шейдеры (shaderpacks)</span>
                    </div>
                    <p class="text-[11px] text-slate-400 mt-0.5">Архивы .zip для Oculus/Iris/OptiFine, автоматически скачиваются игрокам</p>
                  </div>
                  <div>
                    <input type="file" id="shaderFile_${s.id}" multiple accept=".zip" class="hidden" onchange="uploadShaders('${s.id}', this.files)">
                    <button onclick="document.getElementById('shaderFile_${s.id}').click()" class="px-4 py-1.5 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 border border-amber-500/30 text-amber-300 text-xs font-bold flex items-center gap-2 transition-all">
                      <i class="fa-solid fa-plus text-xs"></i>
                      <span>Загрузить .zip</span>
                    </button>
                  </div>
                </div>

                ${s.shadersList.length === 0 ? `
                  <div class="p-6 text-center bg-[#0b0c11] border border-dashed border-[#1a1d2b] rounded-xl text-xs text-slate-500">
                    Шейдеры не загружены. Нажмите «Загрузить .zip» выше.
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
                          <button onclick="deleteShader('${s.id}', '${sh.name}')" title="Удалить" class="text-slate-500 hover:text-red-400 transition-colors p-1">
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
                      <span>Ресурспаки (resourcepacks)</span>
                    </div>
                    <p class="text-[11px] text-slate-400 mt-0.5">Архивы .zip текстур и звуков, автоматически скачиваются в папку игры игрока</p>
                  </div>
                  <div>
                    <input type="file" id="rpFile_${s.id}" multiple accept=".zip" class="hidden" onchange="uploadResourcepacks('${s.id}', this.files)">
                    <button onclick="document.getElementById('rpFile_${s.id}').click()" class="px-4 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-300 text-xs font-bold flex items-center gap-2 transition-all">
                      <i class="fa-solid fa-plus text-xs"></i>
                      <span>Загрузить .zip</span>
                    </button>
                  </div>
                </div>

                ${s.resourcepacksList.length === 0 ? `
                  <div class="p-6 text-center bg-[#0b0c11] border border-dashed border-[#1a1d2b] rounded-xl text-xs text-slate-500">
                    Ресурспаки не загружены. Нажмите «Загрузить .zip» выше.
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
                          <button onclick="deleteResourcepack('${s.id}', '${rp.name}')" title="Удалить" class="text-slate-500 hover:text-red-400 transition-colors p-1">
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
                      Публичный адрес игрового сервера (Домен или внешний IP)
                    </span>
                    <p class="text-[11px] text-slate-400 mt-0.5">По этому адресу лаунчер игроков подключается к серверу: <code class="text-cyan-300 font-mono font-bold">${s.ip}:${s.port}</code></p>
                  </div>
                  <div class="flex items-center gap-2 max-w-md">
                    <input type="text" id="hostInput_${s.id}" value="${s.publicHost || ''}" placeholder="например: mc.example.com" class="flex-1 bg-[#12141c] border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-cyan-300 font-mono focus:border-indigo-500 focus:outline-none">
                    <button onclick="savePublicHost('${s.id}')" class="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-bold text-white transition-all shrink-0">
                      Сохранить
                    </button>
                  </div>
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
        <p class="text-xs text-slate-400">Конфигурация API лаунчера и привязка к DiscoPanel</p>
      </div>

      <!-- Launcher API Connection Card -->
      <div class="bg-[#11131a] border border-[#1b1e2a] rounded-2xl p-6 space-y-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 text-lg shrink-0">
            <i class="fa-solid fa-satellite-dish"></i>
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h2 class="text-sm font-bold text-white">Адрес API для лаунчера игроков</h2>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">Порт ${LAUNCHER_PORT}</span>
            </div>
            <p class="text-xs text-slate-400 mt-0.5">Укажите эту ссылку в лаунчере: «Настройки» → «Адрес сервера»</p>
          </div>
        </div>

        <div class="flex items-center gap-3 pt-2">
          <div class="flex-1 bg-[#0b0c11] border border-slate-700/60 rounded-xl px-4 py-2.5 font-mono text-sm text-cyan-300 select-all">
            <span id="launcherApiUrl">${launcherUrl}</span>
          </div>
          <button onclick="copyLauncherUrl()" id="copyBtn" class="px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center gap-2 transition-all shadow-md shrink-0">
            <i class="fa-solid fa-copy"></i>
            <span id="copyBtnText">Копировать</span>
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
            <h2 class="text-sm font-bold text-white">Привязка DiscoPanel API</h2>
            <p class="text-xs text-slate-400 mt-0.5">Автоматическое обнаружение серверов и загрузка модов</p>
          </div>
        </div>

        <form id="apiConfigForm" onsubmit="saveApiConfig(event)" class="grid grid-cols-1 md:grid-cols-12 gap-3 pt-2">
          <div class="md:col-span-5">
            <label class="text-[11px] font-semibold text-slate-400 block mb-1">Адрес DiscoPanel</label>
            <input type="text" id="dpUrlInput" value="${dpUrl}" class="w-full bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3.5 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none font-mono">
          </div>
          <div class="md:col-span-5">
            <label class="text-[11px] font-semibold text-slate-400 block mb-1">API Токен (с префиксом dp_)</label>
            <input type="password" id="dpTokenInput" value="${dpToken}" placeholder="dp_..." class="w-full bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3.5 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none font-mono">
          </div>
          <div class="md:col-span-2 flex items-end">
            <button type="submit" class="w-full py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-bold text-slate-200 transition-all">
              Сохранить
            </button>
          </div>
        </form>
      </div>

      <!-- Admin Security Card -->
      <div class="bg-[#11131a] border border-[#1b1e2a] rounded-2xl p-6">
        <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 text-lg shrink-0">
              <i class="fa-solid fa-shield-halved"></i>
            </div>
            <div>
              <h2 class="text-sm font-bold text-white">Безопасность администратора</h2>
              <p class="text-xs text-slate-400 mt-0.5">Текущий логин: <b class="text-white font-mono">${currentAdminUser}</b></p>
            </div>
          </div>
          <button onclick="openCredentialsModal()" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold flex items-center gap-2 transition-all shadow-md">
            <i class="fa-solid fa-key"></i>
            <span>Сменить логин и пароль</span>
          </button>
        </div>
      </div>

    </div>

    <!-- ================= SECTION: DASHBOARD ================= -->
    <div id="section_dashboard" class="hidden p-8 max-w-5xl w-full mx-auto space-y-6">
      <div class="pb-4 border-b border-[#161822]">
        <h1 class="text-xl font-black text-white tracking-tight">Dashboard</h1>
        <p class="text-xs text-slate-400">Общая статистика и состояние серверов</p>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div class="p-5 rounded-2xl bg-[#11131a] border border-[#1b1e2a]">
          <div class="text-xs font-bold text-slate-400 uppercase tracking-wider">Всего серверов</div>
          <div class="text-3xl font-black text-white font-mono mt-2">${servers.length}</div>
          <div class="text-[11px] text-emerald-400 mt-1 flex items-center gap-1.5">
            <span class="w-2 h-2 rounded-full bg-emerald-400"></span> ${totalRunning} онлайн
          </div>
        </div>

        <div class="p-5 rounded-2xl bg-[#11131a] border border-[#1b1e2a]">
          <div class="text-xs font-bold text-slate-400 uppercase tracking-wider">Игроков онлайн</div>
          <div class="text-3xl font-black text-emerald-400 font-mono mt-2">${totalPlayersOnline}</div>
          <div class="text-[11px] text-slate-400 mt-1">на всех серверах</div>
        </div>

        <div class="p-5 rounded-2xl bg-[#11131a] border border-[#1b1e2a]">
          <div class="text-xs font-bold text-slate-400 uppercase tracking-wider">Моды и паки</div>
          <div class="text-3xl font-black text-cyan-400 font-mono mt-2">${totalModsCount}</div>
          <div class="text-[11px] text-slate-400 mt-1">${totalShadersCount} шейдеров, ${totalPacksCount} ресурспаков</div>
        </div>
      </div>
    </div>

    <!-- ================= SECTION: API ================= -->
    <div id="section_api" class="hidden p-8 max-w-5xl w-full mx-auto space-y-6">
      <div class="pb-4 border-b border-[#161822]">
        <h1 class="text-xl font-black text-white tracking-tight">API Launcher Endpoints</h1>
        <p class="text-xs text-slate-400">Документация и доступные эндпоинты для лаунчера</p>
      </div>

      <div class="space-y-3">
        <div class="p-4 rounded-xl bg-[#11131a] border border-[#1b1e2a] font-mono text-xs">
          <div class="text-emerald-400 font-bold">GET /api/servers</div>
          <div class="text-slate-400 mt-1 text-[11px]">Список всех серверов для отображения в лаунчере</div>
        </div>
        <div class="p-4 rounded-xl bg-[#11131a] border border-[#1b1e2a] font-mono text-xs">
          <div class="text-emerald-400 font-bold">GET /api/servers/:id/manifest</div>
          <div class="text-slate-400 mt-1 text-[11px]">Манифест синхронизации файлов, модов, шейдеров и ресурспаков</div>
        </div>
        <div class="p-4 rounded-xl bg-[#11131a] border border-[#1b1e2a] font-mono text-xs">
          <div class="text-emerald-400 font-bold">GET /files/:id/*</div>
          <div class="text-slate-400 mt-1 text-[11px]">Прямая скачка файлов клиентом лаунчера</div>
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
          <span>Смена данных администратора</span>
        </div>
        <button type="button" onclick="closeCredentialsModal()" class="text-slate-400 hover:text-white text-sm p-1">
          <i class="fa-solid fa-xmark"></i>
        </button>
      </div>

      <form onsubmit="saveCredentials(event)" class="space-y-3.5">
        <div>
          <label class="text-[11px] font-semibold text-slate-400 block mb-1">Текущий пароль</label>
          <input type="password" id="currentPassInput" required placeholder="Введите текущий пароль" class="w-full bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none">
        </div>

        <div class="pt-2 border-t border-slate-800/60">
          <label class="text-[11px] font-semibold text-slate-400 block mb-1">Новый логин</label>
          <input type="text" id="newUsernameInput" value="${currentAdminUser}" required placeholder="Логин администратора" class="w-full bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none font-mono">
        </div>

        <div>
          <label class="text-[11px] font-semibold text-slate-400 block mb-1">Новый пароль</label>
          <input type="password" id="newPassInput" required placeholder="Минимум 4 символа" class="w-full bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none">
        </div>

        <div>
          <label class="text-[11px] font-semibold text-slate-400 block mb-1">Повторите новый пароль</label>
          <input type="password" id="confirmPassInput" required placeholder="Повторите пароль" class="w-full bg-[#0b0c11] border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none">
        </div>

        <div id="credError" class="hidden p-2.5 rounded-xl bg-red-950/50 border border-red-800/50 text-xs text-red-300"></div>
        <div id="credSuccess" class="hidden p-2.5 rounded-xl bg-emerald-950/50 border border-emerald-800/50 text-xs text-emerald-300"></div>

        <div class="flex items-center justify-end gap-2.5 pt-2">
          <button type="button" onclick="closeCredentialsModal()" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-bold text-slate-300 transition-all">
            Отмена
          </button>
          <button type="submit" id="saveCredBtn" class="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-xs font-bold text-white transition-all shadow-md">
            Сохранить
          </button>
        </div>
      </form>
    </div>
  </div>

  <!-- ================= SCRIPTS ================= -->
  <script>
    function switchNav(nav) {
      const sections = ['servers', 'settings', 'dashboard', 'api'];
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
    }

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
          alert('Ошибка переключения мода: ' + (d.error || 'Ошибка'));
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
        alert('Ошибка сети: ' + err.message);
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
          alert('Настройки успешно сохранены!');
          window.location.reload();
        } else {
          alert('Ошибка: ' + (d.error || 'Не удалось сохранить'));
        }
      } catch (err) {
        alert('Ошибка сети: ' + err.message);
      }
    }

    async function triggerSyncNow() {
      try {
        const res = await fetch('/api/admin/sync-api', { method: 'POST' });
        const d = await res.json();
        if (d.success) {
          alert('Синхронизация с серверами завершена!');
          window.location.reload();
        } else {
          alert('Ошибка: ' + (d.error || 'Ошибка синхронизации'));
        }
      } catch (err) {
        alert('Ошибка сети: ' + err.message);
      }
    }

    function copyLauncherUrl() {
      const text = document.getElementById('launcherApiUrl').textContent.trim();
      navigator.clipboard.writeText(text).then(() => {
        const btnText = document.getElementById('copyBtnText');
        const origText = btnText.textContent;
        btnText.textContent = 'Скопировано!';
        setTimeout(() => { btnText.textContent = origText; }, 2000);
      }).catch(() => {
        const dummy = document.createElement('textarea');
        dummy.value = text;
        document.body.appendChild(dummy);
        dummy.select();
        document.execCommand('copy');
        document.body.removeChild(dummy);
        const btnText = document.getElementById('copyBtnText');
        btnText.textContent = 'Скопировано!';
        setTimeout(() => { btnText.textContent = 'Копировать'; }, 2000);
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
          alert('Публичный адрес сохранен!');
          window.location.reload();
        } else {
          alert('Ошибка: ' + (d.error || 'Не удалось сохранить'));
        }
      } catch (err) {
        alert('Ошибка: ' + err.message);
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
          alert('Успешно загружено модов: ' + d.count);
          window.location.reload();
        } else {
          alert('Ошибка загрузки: ' + (d.error || 'Ошибка'));
        }
      } catch (err) {
        alert('Ошибка загрузки: ' + err.message);
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
          alert('Успешно загружено шейдеров: ' + d.count);
          window.location.reload();
        } else {
          alert('Ошибка загрузки: ' + (d.error || 'Ошибка'));
        }
      } catch (err) {
        alert('Ошибка загрузки: ' + err.message);
      }
    }

    async function deleteShader(serverId, filename) {
      if (!confirm('Удалить шейдер "' + filename + '"?')) return;
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/delete-shader', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename })
        });
        const d = await res.json();
        if (d.success) { window.location.reload(); }
        else { alert('Ошибка: ' + (d.error || 'Ошибка')); }
      } catch (err) { alert('Ошибка: ' + err.message); }
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
          alert('Успешно загружено ресурспаков: ' + d.count);
          window.location.reload();
        } else {
          alert('Ошибка: ' + (d.error || 'Ошибка'));
        }
      } catch (err) {
        alert('Ошибка: ' + err.message);
      }
    }

    async function deleteResourcepack(serverId, filename) {
      if (!confirm('Удалить ресурспак "' + filename + '"?')) return;
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/delete-resourcepack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename })
        });
        const d = await res.json();
        if (d.success) { window.location.reload(); }
        else { alert('Ошибка: ' + (d.error || 'Ошибка')); }
      } catch (err) { alert('Ошибка: ' + err.message); }
    }

    async function deleteMod(serverId, filename) {
      if (!confirm('Удалить клиентский мод "' + filename + '"?')) return;
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/delete-mod', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename })
        });
        const d = await res.json();
        if (d.success) { window.location.reload(); }
        else { alert('Ошибка: ' + (d.error || 'Ошибка')); }
      } catch (err) { alert('Ошибка: ' + err.message); }
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
        errBox.textContent = 'Логин не может быть пустым!';
        errBox.classList.remove('hidden');
        return;
      }
      if (newPassword !== confirmPassword) {
        errBox.textContent = 'Новые пароли не совпадают!';
        errBox.classList.remove('hidden');
        return;
      }
      if (newPassword.length < 4) {
        errBox.textContent = 'Пароль должен быть не менее 4 символов!';
        errBox.classList.remove('hidden');
        return;
      }

      const btn = document.getElementById('saveCredBtn');
      btn.disabled = true;
      btn.textContent = 'Сохранение...';

      try {
        const res = await fetch('/api/admin/change-credentials', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ currentPassword, newUsername, newPassword })
        });
        const d = await res.json();
        if (d.success) {
          succBox.textContent = 'Данные успешно сохранены! Перезагрузка...';
          succBox.classList.remove('hidden');
          setTimeout(() => window.location.reload(), 1200);
        } else {
          errBox.textContent = d.error || 'Ошибка сохранения';
          errBox.classList.remove('hidden');
        }
      } catch (err) {
        errBox.textContent = 'Ошибка сети: ' + err.message;
        errBox.classList.remove('hidden');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Сохранить';
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
    db.prepare('UPDATE servers SET ip = ? WHERE id = ?').run(cleanHost, serverId);
  } else {
    // Revert to DiscoPanel IP
    const dpUrl = getSetting('discopanel_url', 'http://192.168.10.127:8080');
    let fallbackIp = '192.168.10.127';
    try { fallbackIp = new URL(dpUrl).hostname; } catch(e) {}
    db.prepare('UPDATE servers SET ip = ? WHERE id = ?').run(fallbackIp, serverId);
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
  if (!filename) return res.status(400).json({ success: false, error: 'Имя файла не указано' });

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
  if (files.length === 0) return res.status(400).json({ success: false, error: 'Файлы не выбраны' });

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
  const modsDir = path.join(SERVERS_DIR, serverId, 'mods');
  const count = fs.existsSync(modsDir) ? fs.readdirSync(modsDir).filter(f => f.endsWith('.jar')).length : 0;
  db.prepare('UPDATE servers SET total_mods = ? WHERE id = ?').run(count, serverId);

  res.json({ success: true, count: files.length, files: addedNames });
});

// Delete mod
adminApp.post('/api/admin/servers/:id/delete-mod', requireAdminAuth, (req, res) => {
  const serverId = req.params.id;
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ success: false, error: 'Имя файла не указано' });

  const safeFilename = path.basename(filename);
  const targetPath = path.join(SERVERS_DIR, serverId, 'mods', safeFilename);
  if (fs.existsSync(targetPath)) {
    fs.unlinkSync(targetPath);
  }

  // Remove from client_mods.json
  const clientModsPath = path.join(SERVERS_DIR, serverId, 'client_mods.json');
  try {
    if (fs.existsSync(clientModsPath)) {
      let clientMods = JSON.parse(fs.readFileSync(clientModsPath, 'utf8'));
      clientMods = clientMods.filter(n => n !== safeFilename);
      fs.writeFileSync(clientModsPath, JSON.stringify(clientMods, null, 2));
    }
  } catch (e) {}

  // Update total_mods in DB
  const modsDir = path.join(SERVERS_DIR, serverId, 'mods');
  const count = fs.existsSync(modsDir) ? fs.readdirSync(modsDir).filter(f => f.endsWith('.jar')).length : 0;
  db.prepare('UPDATE servers SET total_mods = ? WHERE id = ?').run(count, serverId);

  res.json({ success: true });
});

// Upload shaders (.zip)
adminApp.post('/api/admin/servers/:id/upload-shader', requireAdminAuth, shaderUpload.array('shaders', 20), (req, res) => {
  const files = req.files || [];
  if (files.length === 0) return res.status(400).json({ success: false, error: 'Файлы не выбраны' });
  res.json({ success: true, count: files.length, files: files.map(f => f.filename) });
});

// Delete shader (.zip)
adminApp.post('/api/admin/servers/:id/delete-shader', requireAdminAuth, (req, res) => {
  const serverId = req.params.id;
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ success: false, error: 'Имя файла не указано' });

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
  if (files.length === 0) return res.status(400).json({ success: false, error: 'Файлы не выбраны' });
  res.json({ success: true, count: files.length, files: files.map(f => f.filename) });
});

// Delete resourcepack (.zip)
adminApp.post('/api/admin/servers/:id/delete-resourcepack', requireAdminAuth, (req, res) => {
  const serverId = req.params.id;
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ success: false, error: 'Имя файла не указано' });

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
