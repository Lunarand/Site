const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Filter = require('bad-words');
const UAParser = require('ua-parser-js');

const app = express();
const filter = new Filter();
const port = 3000;

app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
}

const storage = multer.diskStorage({
  destination: './uploads',
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif|webp/;
    const mimetype = filetypes.test(file.mimetype);
    if (mimetype) return cb(null, true);
    cb(new Error('Only images are allowed!'));
  }
});

// -------------------- AUTH / STATE --------------------
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";
const ADMIN_TOKEN = "admin_token_active"; // kept same pattern as your existing UI expects

let maintenanceMode = false;
let bannedIps = new Set();
let posts = [];    // newest appended; UI reverses
let reports = [];  // {id, postId, reason, message, reporterIp, timestamp}

// -------------------- IP HELPERS --------------------
function getClientIp(req) {
  // Cloudflare Tunnel commonly sets CF-Connecting-IP
  const cf = req.headers['cf-connecting-ip'];
  if (cf) return String(cf).split(',')[0].trim();

  // Standard reverse proxy header
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();

  // Express / Node fallback
  return (req.socket && req.socket.remoteAddress) ? String(req.socket.remoteAddress) : "unknown";
}

function isBanned(req) {
  const ip = getClientIp(req);
  return bannedIps.has(ip);
}

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (token && token === ADMIN_TOKEN) return next();
  return res.status(403).json({ error: "Admin only" });
}

function requireNotBannedAndNotMaintenance(req, res, next) {
  if (isBanned(req)) return res.status(403).json({ error: "You are banned." });
  if (maintenanceMode) return res.status(403).json({ error: "Site under maintenance." });
  next();
}

function nowStr() {
  return new Date().toLocaleString();
}

// -------------------- BASIC ROUTES --------------------
app.get('/api/status', (req, res) => {
  res.json({ maintenance: maintenanceMode });
});

app.post('/api/login', (req, res) => {
  const { password } = req.body || {};
  if (password === ADMIN_PASSWORD) {
    return res.json({ success: true, token: ADMIN_TOKEN });
  }
  return res.status(401).json({ error: "Wrong password" });
});

app.get('/api/posts', (req, res) => {
  // normal users must never see IPs
  const safe = posts.map(p => ({
    id: p.id,
    title: p.title,
    text: p.text,
    image: p.image,
    date: p.date,
    likes: p.likes,
    dislikes: p.dislikes,
    comments: p.comments.length
  }));
  res.json(safe.reverse());
});

app.get('/api/posts/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Post not found" });

  // normal users must never see IPs
  return res.json({
    id: post.id,
    title: post.title,
    text: post.text,
    image: post.image,
    date: post.date,
    likes: post.likes,
    dislikes: post.dislikes,
    comments: post.comments.map(c => ({ text: c.text, date: c.date }))
  });
});

// -------------------- UPLOAD (CREATE POST) --------------------
app.post('/api/upload', requireNotBannedAndNotMaintenance, upload.single('image'), (req, res) => {
  try {
    const title = (req.body.title || '').toString();
    const text = (req.body.text || '').toString();

    if (filter.isProfane(title) || filter.isProfane(text)) {
      return res.status(400).json({ error: 'Profanity detected.' });
    }

    const ip = getClientIp(req);
    const ua = req.headers['user-agent'] || '';
    const createdAt = Date.now();

    const newPost = {
      id: createdAt,
      title,
      text,
      image: req.file ? `/uploads/${req.file.filename}` : null,
      date: nowStr(),

      // interactions
      likes: 0,
      dislikes: 0,
      comments: [],

      // anti-spam / per-IP tracking
      likedBy: new Set(),
      dislikedBy: new Set(),

      // admin-only metadata
      ownerIp: ip,
      ownerUa: ua,
      ownerCreatedAt: createdAt,
      ownerHeaders: {
        acceptLanguage: req.headers['accept-language'] || '',
        referer: req.headers['referer'] || '',
        cfRay: req.headers['cf-ray'] || '',
        cfIpcountry: req.headers['cf-ipcountry'] || ''
      }
    };

    posts.push(newPost);
    return res.status(201).json({
      id: newPost.id,
      title: newPost.title,
      text: newPost.text,
      image: newPost.image,
      date: newPost.date,
      likes: newPost.likes,
      dislikes: newPost.dislikes,
      comments: 0
    });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

// -------------------- LIKE / DISLIKE --------------------
app.post('/api/posts/:id/like', requireNotBannedAndNotMaintenance, (req, res) => {
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Post not found" });

  const ip = getClientIp(req);

  // prevent multiple votes from same IP
  if (post.likedBy.has(ip)) return res.status(400).json({ error: "Already liked" });

  // if previously disliked, remove dislike
  if (post.dislikedBy.has(ip)) {
    post.dislikedBy.delete(ip);
    post.dislikes = Math.max(0, post.dislikes - 1);
  }

  post.likedBy.add(ip);
  post.likes += 1;

  return res.json({ likes: post.likes, dislikes: post.dislikes });
});

app.post('/api/posts/:id/dislike', requireNotBannedAndNotMaintenance, (req, res) => {
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Post not found" });

  const ip = getClientIp(req);

  if (post.dislikedBy.has(ip)) return res.status(400).json({ error: "Already disliked" });

  if (post.likedBy.has(ip)) {
    post.likedBy.delete(ip);
    post.likes = Math.max(0, post.likes - 1);
  }

  post.dislikedBy.add(ip);
  post.dislikes += 1;

  return res.json({ likes: post.likes, dislikes: post.dislikes });
});

// -------------------- COMMENTS --------------------
app.post('/api/posts/:id/comment', requireNotBannedAndNotMaintenance, (req, res) => {
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Post not found" });

  const text = (req.body && req.body.text ? String(req.body.text) : "").trim();
  if (!text) return res.status(400).json({ error: "Empty comment" });

  if (filter.isProfane(text)) return res.status(400).json({ error: "Profanity detected." });

  post.comments.push({ text, date: nowStr() });
  return res.json({ comments: post.comments.length });
});

// -------------------- REPORTING --------------------
app.post('/api/posts/:id/report', requireNotBannedAndNotMaintenance, (req, res) => {
  const postId = parseInt(req.params.id);
  const post = posts.find(p => p.id === postId);
  if (!post) return res.status(404).json({ error: "Post not found" });

  const reason = (req.body && req.body.reason ? String(req.body.reason) : "").trim();
  const message = (req.body && req.body.message ? String(req.body.message) : "").trim();

  const allowed = new Set([
    "Spam",
    "Hate or abuse",
    "Illegal content",
    "Harassment",
    "Misinformation",
    "Something else"
  ]);

  if (!allowed.has(reason)) return res.status(400).json({ error: "Invalid reason" });
  if (reason === "Something else" && !message) return res.status(400).json({ error: "Please explain (Something else)" });

  const reporterIp = getClientIp(req);

  const r = {
    id: Date.now(),
    postId,
    reason,
    message: message || "",
    reporterIp,
    timestamp: nowStr()
  };
  reports.push(r);

  return res.json({ success: true });
});

// -------------------- ADMIN STATUS --------------------
app.get('/api/admin/status', requireAdmin, (req, res) => {
  return res.json({
    maintenance: maintenanceMode,
    bannedCount: bannedIps.size,
    reportsCount: reports.length
  });
});

// -------------------- ADMIN POSTS --------------------
app.get('/api/admin/posts', requireAdmin, (req, res) => {
  const out = posts.slice().reverse().map(p => ({
    id: p.id,
    title: p.title,
    text: p.text,
    image: p.image,
    date: p.date,
    likes: p.likes,
    dislikes: p.dislikes,
    comments: p.comments,
    ownerIp: p.ownerIp
  }));
  res.json(out);
});

app.delete('/api/admin/posts/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const before = posts.length;
  posts = posts.filter(p => p.id !== id);
  // also remove related reports
  reports = reports.filter(r => r.postId !== id);

  if (posts.length === before) return res.status(404).json({ error: "Post not found" });
  return res.json({ success: true });
});

// -------------------- ADMIN REPORTS --------------------
app.get('/api/admin/reports', requireAdmin, (req, res) => {
  const out = reports.slice().reverse().map(r => {
    const p = posts.find(x => x.id === r.postId);
    return {
      id: r.id,
      postId: r.postId,
      reason: r.reason,
      message: r.message,
      reporterIp: r.reporterIp,
      timestamp: r.timestamp,
      post: p ? {
        id: p.id,
        title: p.title,
        text: p.text,
        ownerIp: p.ownerIp
      } : null
    };
  });
  res.json(out);
});

app.post('/api/admin/reports/:id/ignore', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const before = reports.length;
  reports = reports.filter(r => r.id !== id);
  if (before === reports.length) return res.status(404).json({ error: "Report not found" });
  return res.json({ success: true });
});

// -------------------- ADMIN BANS --------------------
app.get('/api/admin/bans', requireAdmin, (req, res) => {
  res.json({ banned: Array.from(bannedIps.values()) });
});

app.post('/api/admin/ban', requireAdmin, (req, res) => {
  const ip = (req.body && req.body.ip ? String(req.body.ip) : "").trim();
  if (!ip) return res.status(400).json({ error: "Missing IP" });
  bannedIps.add(ip);
  return res.json({ success: true });
});

app.post('/api/admin/unban', requireAdmin, (req, res) => {
  const ip = (req.body && req.body.ip ? String(req.body.ip) : "").trim();
  if (!ip) return res.status(400).json({ error: "Missing IP" });
  bannedIps.delete(ip);
  return res.json({ success: true });
});

// -------------------- ADMIN MAINTENANCE --------------------
app.post('/api/admin/maintenance', requireAdmin, (req, res) => {
  const enabled = !!(req.body && req.body.enabled);
  maintenanceMode = enabled;
  return res.json({ success: true, maintenance: maintenanceMode });
});

// -------------------- ✅ ADMIN SAFETY DETAILS (NEW) --------------------
// Optional IP geolocation: set IPINFO_TOKEN in env (GitHub Actions secret) to enable.
async function ipInfoLookup(ip) {
  const token = process.env.IPINFO_TOKEN;
  if (!token) return null;

  try {
    // Node 18 has global fetch
    const resp = await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}?token=${encodeURIComponent(token)}`, {
      headers: { 'Accept': 'application/json' }
    });
    if (!resp.ok) return null;
    const data = await resp.json();

    // data: { city, region, country, org, timezone, loc, ... }
    return {
      city: data.city || null,
      region: data.region || null,
      country: data.country || null,
      ispOrg: data.org || null,
      timezone: data.timezone || null
    };
  } catch {
    return null;
  }
}

app.get('/api/admin/posts/:id/details', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Post not found" });

  const ua = post.ownerUa || "";
  const parsed = new UAParser(ua).getResult();

  const ip = post.ownerIp || "unknown";
  const geo = await ipInfoLookup(ip);

  // Admin-only details response (never exposed to normal users)
  return res.json({
    postId: post.id,
    createdAt: post.ownerCreatedAt ? new Date(post.ownerCreatedAt).toISOString() : null,

    ip,
    device: {
      type: parsed.device && parsed.device.type ? parsed.device.type : "desktop/unknown",
      vendor: parsed.device && parsed.device.vendor ? parsed.device.vendor : null,
      model: parsed.device && parsed.device.model ? parsed.device.model : null
    },
    browser: {
      name: parsed.browser && parsed.browser.name ? parsed.browser.name : null,
      version: parsed.browser && parsed.browser.version ? parsed.browser.version : null
    },
    os: {
      name: parsed.os && parsed.os.name ? parsed.os.name : null,
      version: parsed.os && parsed.os.version ? parsed.os.version : null
    },

    network: {
      // best-effort hints; may be empty depending on tunnel/proxy
      acceptLanguage: post.ownerHeaders.acceptLanguage || null,
      cfRay: post.ownerHeaders.cfRay || null,
      cfIpCountry: post.ownerHeaders.cfIpcountry || null,
      referer: post.ownerHeaders.referer || null
    },

    geo: geo ? geo : {
      city: null,
      region: null,
      country: null,
      ispOrg: null,
      timezone: null
    },

    notes: {
      privacy: "City/ISP require a geo provider. Set IPINFO_TOKEN to enable lookup."
    }
  });
});

app.listen(port, () => console.log(`Server running on ${port}`));
