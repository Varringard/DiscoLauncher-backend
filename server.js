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
const SKINS_DIR = path.join(UPLOADS_DIR, 'skins');
const CAPES_DIR = path.join(UPLOADS_DIR, 'capes');
const SERVERS_DIR = path.join(DATA_DIR, 'servers');

[DATA_DIR, UPLOADS_DIR, SKINS_DIR, CAPES_DIR, SERVERS_DIR].forEach(dir => {
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
    skin_url TEXT,
    cape_url TEXT,
    model TEXT DEFAULT 'classic',
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

// Multer for skin uploads
const skinStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, SKINS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.png';
    cb(null, `${req.user ? req.user.uuid : 'temp_' + Date.now()}${ext}`);
  }
});
const skinUpload = multer({ storage: skinStorage, limits: { fileSize: 2 * 1024 * 1024 } });

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
      INSERT INTO users (username, password_hash, uuid, skin_url)
      VALUES (?, ?, ?, ?)
    `).run(username, hash, uuid, `/api/skins/${username}`);

    const user = { id: result.lastInsertRowid, username, uuid, skinUrl: `/api/skins/${username}` };
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
      uuid: user.uuid,
      skinUrl: user.skin_url || `/api/skins/${user.username}`,
      model: user.model || 'classic'
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

// Skins Routes
launcherApp.post('/api/skins/upload', authenticatePlayerToken, skinUpload.single('skin'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
    const { model } = req.body;
    const skinRelUrl = `/uploads/skins/${path.basename(req.file.path)}`;

    db.prepare('UPDATE users SET skin_url = ?, model = ? WHERE id = ?')
      .run(skinRelUrl, model === 'slim' ? 'slim' : 'classic', req.user.id);

    res.json({ success: true, skinUrl: skinRelUrl, model: model || 'classic' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

launcherApp.get('/api/skins/:username', async (req, res) => {
  const username = req.params.username;
  const user = db.prepare('SELECT * FROM users WHERE lower(username) = lower(?)').get(username);

  if (user && user.skin_url && user.skin_url.startsWith('/uploads/')) {
    const filePath = path.join(__dirname, user.skin_url);
    if (fs.existsSync(filePath)) {
      res.setHeader('Content-Type', 'image/png');
      return fs.createReadStream(filePath).pipe(res);
    }
  }

  const elyUrl = `https://skin.ely.by/skins/${encodeURIComponent(username)}.png`;
  try {
    const headRes = await fetch(elyUrl, { method: 'HEAD' });
    if (headRes.ok) return res.redirect(elyUrl);
  } catch (e) {}

  return res.redirect(`https://minotar.net/skin/${encodeURIComponent(username)}`);
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

  if (!fs.existsSync(serverDir)) {
    fs.mkdirSync(path.join(serverDir, 'mods'), { recursive: true });
    fs.mkdirSync(path.join(serverDir, 'config'), { recursive: true });
  }

  function scanDir(currentDir, relativePrefix = '') {
    let result = [];
    if (!fs.existsSync(currentDir)) return result;
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const ent of entries) {
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

// Yggdrasil Profile / Skin Routes
launcherApp.get('/api/yggdrasil', (req, res) => {
  res.json({
    meta: { serverName: 'ExodusWorld Auth', implementationName: 'exodus-backend', implementationVersion: '1.0.0' },
    skinDomains: ['192.168.10.123', '192.168.10.148', 'ely.by', 'mojang.com']
  });
});

launcherApp.get('/api/yggdrasil/sessionserver/session/minecraft/profile/:uuid', (req, res) => {
  const { uuid } = req.params;
  const user = db.prepare('SELECT * FROM users WHERE uuid = ?').get(uuid);
  if (!user) return res.status(204).send();

  const skinUrl = user.skin_url ? `http://192.168.10.123:${LAUNCHER_PORT}${user.skin_url}` : `https://skin.ely.by/skins/${user.username}.png`;
  const texturesObj = {
    timestamp: Date.now(),
    profileId: user.uuid,
    profileName: user.username,
    textures: { SKIN: { url: skinUrl, metadata: { model: user.model || 'classic' } } }
  };

  res.json({
    id: user.uuid,
    name: user.username,
    properties: [{ name: 'textures', value: Buffer.from(JSON.stringify(texturesObj)).toString('base64') }]
  });
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
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = jwt.sign({ role: 'admin', user: ADMIN_USER }, JWT_SECRET, { expiresIn: '7d' });
    res.setHeader('Set-Cookie', `admin_token=${token}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax`);
    return res.json({ success: true, token });
  }
  return res.status(401).json({ success: false, error: 'Неверный логин или пароль' });
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

    s.modsList = allMods.map(m => ({
      name: m,
      isClient: clientModsSet.has(m)
    }));
    s.totalMods = allMods.length;
    s.isModsSyncEnabled = getSetting('sync_mods_' + s.id, 'true') !== 'false';
    const customHost = getSetting('public_server_host_' + s.id) || getSetting('public_server_host');
    if (customHost && customHost.trim()) {
      s.ip = customHost.trim();
    }
    s.publicHost = customHost || '';
  });

  const html = `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>DiscoLauncher - Панель управления</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body { background-color: #0b0f19; color: #e2e8f0; font-family: system-ui, -apple-system, sans-serif; }
  </style>
</head>
<body class="min-h-screen p-8">
  <div class="max-w-6xl mx-auto">
    <!-- Header -->
    <header class="flex items-center justify-between pb-6 border-b border-indigo-950/80 mb-8">
      <div class="flex items-center gap-4">
        <div class="w-12 h-12 rounded-2xl bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center text-xl text-indigo-400 shadow-lg shadow-indigo-600/20">
          <i class="fa-solid fa-gamepad"></i>
        </div>
        <div>
          <div class="flex items-center gap-3">
            <h1 class="text-2xl font-black tracking-wide text-white">DiscoLauncher</h1>
            <span class="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 text-xs font-mono border border-indigo-500/30">Админ-панель (порт ${ADMIN_PORT})</span>
            <span class="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 text-xs font-mono border border-cyan-500/30">API лаунчера: :${LAUNCHER_PORT}</span>
          </div>
          <p class="text-xs text-slate-400 mt-1">Автоматическая синхронизация серверов и модов через DiscoPanel API</p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div class="px-3 py-2 rounded-xl bg-slate-900/80 border border-slate-800 text-xs text-slate-300 flex items-center gap-2">
          <i class="fa-solid fa-user-shield text-indigo-400"></i>
          <span class="font-bold font-mono text-white">varringard</span>
        </div>
        <button onclick="triggerSyncNow()" class="px-4 py-2 rounded-xl bg-indigo-600/30 hover:bg-indigo-600/50 border border-indigo-500/50 text-xs font-bold text-indigo-200 flex items-center gap-2 transition-all">
          <i class="fa-solid fa-arrows-rotate"></i> Синхронизировать
        </button>
        <a href="${dpUrl}" target="_blank" class="px-4 py-2 rounded-xl bg-purple-950/60 hover:bg-purple-900/60 border border-purple-500/40 text-xs font-bold text-purple-300 flex items-center gap-2 transition-all">
          <i class="fa-solid fa-sliders"></i> DiscoPanel
        </a>
        <button onclick="logoutAdmin()" title="Выйти из панели" class="px-3 py-2 rounded-xl bg-red-950/50 hover:bg-red-900/60 border border-red-800/50 text-xs font-bold text-red-300 flex items-center gap-1.5 transition-all">
          <i class="fa-solid fa-right-from-bracket"></i> Выйти
        </button>
      </div>
    </header>

    <!-- Launcher API Connection Card -->
    <div class="bg-gradient-to-r from-cyan-950/50 via-[#121826] to-indigo-950/40 border border-cyan-500/30 rounded-3xl p-6 mb-8 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-5">
      <div class="flex items-center gap-4">
        <div class="w-12 h-12 rounded-2xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-xl text-cyan-400 shrink-0 shadow-lg shadow-cyan-500/20">
          <i class="fa-solid fa-satellite-dish"></i>
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h2 class="text-sm font-bold text-white uppercase tracking-wider">Адрес API для лаунчера игроков</h2>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">Порт ${LAUNCHER_PORT}</span>
          </div>
          <p class="text-xs text-slate-400 mt-1">
            Укажите эту ссылку в лаунчере: вкладка <b class="text-slate-200">«Настройки»</b> → поле <b class="text-slate-200">«Адрес сервера»</b>
          </p>
        </div>
      </div>
      <div class="flex items-center gap-2 w-full md:w-auto">
        <div class="flex items-center bg-slate-900/90 border border-cyan-500/40 rounded-2xl px-4 py-2.5 font-mono text-sm text-cyan-300 select-all shadow-inner">
          <span id="launcherApiUrl">${launcherUrl}</span>
        </div>
        <button onclick="copyLauncherUrl()" id="copyBtn" class="px-4 py-2.5 rounded-2xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center gap-2 transition-all shadow-lg shadow-cyan-600/30 shrink-0">
          <i class="fa-solid fa-copy"></i>
          <span id="copyBtnText">Копировать</span>
        </button>
      </div>
    </div>

    <!-- DiscoPanel API Settings Box -->
    <div class="bg-[#121826] border border-indigo-950 rounded-3xl p-6 mb-8 shadow-xl">
      <div class="mb-4">
        <h2 class="text-base font-bold text-white flex items-center gap-2">
          <i class="fa-solid fa-link text-indigo-400"></i> Привязка DiscoPanel API
        </h2>
        <p class="text-xs text-slate-400 mt-1">Лаунчер использует API для автоматического обнаружения серверов и загрузки модов</p>
      </div>

      <form id="apiConfigForm" onsubmit="saveApiConfig(event)" class="grid grid-cols-1 md:grid-cols-12 gap-4">
        <div class="md:col-span-5">
          <label class="text-[11px] font-semibold text-slate-400 block mb-1">Адрес DiscoPanel</label>
          <input type="text" id="dpUrlInput" value="${dpUrl}" class="w-full bg-slate-900/80 border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none font-mono">
        </div>
        <div class="md:col-span-5">
          <label class="text-[11px] font-semibold text-slate-400 block mb-1">API Токен (с префиксом dp_)</label>
          <input type="password" id="dpTokenInput" value="${dpToken}" placeholder="dp_..." class="w-full bg-slate-900/80 border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none font-mono">
        </div>
        <div class="md:col-span-2 flex items-end">
          <button type="submit" class="w-full py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-bold text-slate-200 transition-all">
            Сохранить
          </button>
        </div>
      </form>
    </div>

    <!-- Servers in Launcher -->
    <div class="bg-[#121826] border border-indigo-950 rounded-3xl p-6 mb-8">
      <div class="flex items-center justify-between mb-6">
        <div>
          <h2 class="text-lg font-bold text-white flex items-center gap-2">
            <i class="fa-solid fa-server text-cyan-400"></i> Серверы в лаунчере (${servers.length})
          </h2>
          <p class="text-xs text-slate-400">Управление синхронизацией и загрузка клиентских модов для каждого сервера</p>
        </div>
      </div>

      <div class="grid grid-cols-1 gap-6">
        ${servers.map(s => `
          <div class="p-6 rounded-3xl bg-[#0e1422] border border-slate-800 space-y-5">
            <!-- Server Header -->
            <div class="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
              <div class="flex items-center gap-3">
                <span class="w-3 h-3 rounded-full ${s.status === 'online' ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}"></span>
                <div>
                  <div class="flex flex-wrap items-center gap-2">
                    <span class="text-lg font-black text-white">${s.name}</span>
                    <span class="px-2 py-0.5 rounded-lg bg-indigo-500/20 text-indigo-300 text-xs font-mono font-bold">${s.version} (${s.modloader})</span>
                    <span class="px-2 py-0.5 rounded-lg bg-slate-800 text-slate-300 text-xs font-mono">${s.ip}:${s.port}</span>
                    <span class="px-2 py-0.5 rounded-lg bg-slate-800 text-slate-400 text-xs font-mono">0 / ${s.maxOnline} слотов</span>
                  </div>
                  <p class="text-xs text-slate-400 mt-1">${s.description || ''}</p>
                </div>
              </div>
            </div>

            <!-- Public Domain / IP for Minecraft -->
            <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 rounded-2xl bg-slate-900/60 border border-slate-800">
              <div class="flex items-center gap-3">
                <div class="w-8 h-8 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 text-xs shrink-0">
                  <i class="fa-solid fa-globe"></i>
                </div>
                <div>
                  <span class="text-xs font-bold text-white">Публичный адрес игрового сервера (Домен или внешний IP)</span>
                  <p class="text-[11px] text-slate-400">По этому адресу игроки лаунчера подключаются к Minecraft: <code class="text-cyan-300 font-mono">${s.ip}:${s.port}</code></p>
                </div>
              </div>
              <div class="flex items-center gap-2 w-full sm:w-auto">
                <input type="text" id="hostInput_${s.id}" value="${s.publicHost || ''}" placeholder="например: mc.Varringard.site" class="bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs text-cyan-300 font-mono focus:border-indigo-500 focus:outline-none w-full sm:w-56">
                <button onclick="savePublicHost('${s.id}')" class="px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-xs font-bold text-white transition-all shadow-md shadow-indigo-600/20 shrink-0">
                  Сохранить
                </button>
              </div>
            </div>

            <!-- Row: DiscoPanel Sync Toggle + Client Mods Upload -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <!-- DiscoPanel Sync Toggle -->
              <div class="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 flex items-center justify-between gap-4">
                <div>
                  <div class="flex items-center gap-2">
                    <i class="fa-solid fa-arrows-rotate ${s.isModsSyncEnabled ? 'text-indigo-400' : 'text-slate-500'}"></i>
                    <span class="text-xs font-bold text-white">Синхронизация с DiscoPanel</span>
                  </div>
                  <p class="text-[11px] text-slate-400 mt-1">
                    ${s.isModsSyncEnabled ? 'Включена: серверные моды подтягиваются из DiscoPanel' : 'Отключена: загрузка модов из DiscoPanel заблокирована'}
                  </p>
                </div>
                <label class="relative inline-flex items-center cursor-pointer shrink-0">
                  <input type="checkbox" ${s.isModsSyncEnabled ? 'checked' : ''} onchange="toggleSync('${s.id}', this.checked)" class="sr-only peer">
                  <div class="w-11 h-6 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
                </label>
              </div>

              <!-- Client Mods Upload Area -->
              <div class="p-4 rounded-2xl bg-cyan-950/20 border border-cyan-900/40 flex items-center justify-between gap-4">
                <div>
                  <div class="flex items-center gap-2 text-cyan-300 font-bold text-xs">
                    <i class="fa-solid fa-cloud-arrow-up"></i>
                    <span>Клиентские моды (только лаунчер)</span>
                  </div>
                  <p class="text-[11px] text-slate-400 mt-1">
                    Отдаются игрокам, но НЕ затрагивают сервер Minecraft
                  </p>
                </div>
                <div class="shrink-0">
                  <input type="file" id="modFile_${s.id}" multiple accept=".jar" class="hidden" onchange="uploadClientMods('${s.id}', this.files)">
                  <button onclick="document.getElementById('modFile_${s.id}').click()" class="px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center gap-2 transition-all shadow-lg shadow-cyan-600/20">
                    <i class="fa-solid fa-plus"></i> Загрузить .jar
                  </button>
                </div>
              </div>
            </div>

            <!-- Mods list -->
            <div>
              <div class="flex items-center justify-between mb-2.5">
                <span class="text-xs font-bold text-slate-300">
                  Установленные моды сборки (${s.totalMods})
                </span>
                <span class="text-[11px] text-slate-500">
                  Клиентские моды отмечены синим и удаляются по кнопке корзины
                </span>
              </div>
              ${s.modsList.length === 0 ? `
                <div class="p-4 rounded-xl bg-slate-900/40 border border-dashed border-slate-800 text-center text-xs text-slate-500">
                  В этой сборке пока нет модов. Включите синхронизацию с DiscoPanel или загрузите клиентские моды выше.
                </div>
              ` : `
                <div class="flex flex-wrap gap-2">
                  ${s.modsList.map(m => `
                    <div class="flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-mono ${m.isClient ? 'bg-cyan-950/50 border border-cyan-800/60 text-cyan-200 shadow-sm' : 'bg-slate-900/80 border border-slate-800 text-slate-300'}">
                      <i class="fa-solid fa-cube ${m.isClient ? 'text-cyan-400' : 'text-indigo-400'}"></i>
                      <span class="truncate max-w-[260px]">${m.name}</span>
                      <span class="text-[9px] px-1.5 py-0.5 rounded font-sans font-bold uppercase ${m.isClient ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'bg-slate-800 text-slate-400'}">
                        ${m.isClient ? 'Клиентский' : 'DiscoPanel'}
                      </span>
                      <button onclick="deleteMod('${s.id}', '${m.name}')" title="Удалить мод" class="text-slate-500 hover:text-red-400 transition-colors ml-1 p-0.5">
                        <i class="fa-solid fa-trash-can text-xs"></i>
                      </button>
                    </div>
                  `).join('')}
                </div>
              `}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  </div>

  <script>
    async function logoutAdmin() {
      try {
        await fetch('/api/logout', { method: 'POST' });
      } catch(e) {}
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
          alert('Настройки сохранены! Серверы обновятся автоматически.');
          window.location.reload();
        }
      } catch (err) {
        alert('Ошибка сохранения: ' + err.message);
      }
    }

    async function toggleSync(serverId, enabled) {
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/toggle-sync', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled })
        });
        const d = await res.json();
        if (d.success) {
          window.location.reload();
        } else {
          alert('Ошибка переключения синхронизации: ' + (d.error || 'Ошибка'));
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
          alert('Успешно загружено клиентских модов: ' + d.count);
          window.location.reload();
        } else {
          alert('Ошибка загрузки: ' + (d.error || 'Ошибка'));
        }
      } catch (err) {
        alert('Ошибка загрузки: ' + err.message);
      }
    }

    async function deleteMod(serverId, filename) {
      if (!confirm('Удалить мод "' + filename + '"?')) return;
      try {
        const res = await fetch('/api/admin/servers/' + serverId + '/delete-mod', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename })
        });
        const d = await res.json();
        if (d.success) {
          window.location.reload();
        } else {
          alert('Ошибка удаления: ' + (d.error || 'Ошибка'));
        }
      } catch (err) {
        alert('Ошибка удаления: ' + err.message);
      }
    }

    async function triggerSyncNow() {
      try {
        const res = await fetch('/api/admin/sync-api', { method: 'POST' });
        const d = await res.json();
        if (d.success) {
          alert('Синхронизация с DiscoPanel завершена!');
          window.location.reload();
        } else {
          alert('Ошибка синхронизации: ' + (d.error || 'Ошибка'));
        }
      } catch (err) {
    function copyLauncherUrl() {
      const text = document.getElementById('launcherApiUrl').textContent.trim();
      navigator.clipboard.writeText(text).then(() => {
        const btnText = document.getElementById('copyBtnText');
        const origText = btnText.textContent;
        btnText.textContent = 'Скопировано!';
        setTimeout(() => {
          btnText.textContent = origText;
        }, 2000);
      }).catch(() => {
        // Fallback
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
