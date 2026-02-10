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

// -------------------- MULTER (MULTI-FILE, MANY TYPES) --------------------
// NOTE: GitHub Actions runner disk is limited, but we allow "high" limits here.
const storage = multer.diskStorage({
  destination: './uploads',
  filename: (req, file, cb) => {
    const safeExt = path.extname(file.originalname || '').slice(0, 12);
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1e9) + safeExt);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 500 * 1024 * 1024,  // 500MB per file (high)
    files: 50                      // up to 50 files per post
  },
  fileFilter: (req, file, cb) => {
    // Allow almost anything. (You can restrict later if you want.)
    cb(null, true);
  }
});

// -------------------- AUTH / STATE --------------------
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";
const ADMIN_TOKEN = "admin_token_active";

let maintenanceMode = false;
let bannedIps = new Set();

let posts = [];   // In-memory
let reports = []; // {id, postId, reason, message, reporterIp, timestamp}

// -------------------- IP HELPERS --------------------
function getClientIp(req) {
  const cf = req.headers['cf-connecting-ip'];
  if (cf) return String(cf).split(',')[0].trim();

  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();

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

function normalizeAttachmentsFromLegacy(post) {
  // Older versions had single "image" field.
  // This keeps backward compatibility without removing anything.
  if (!post.attachments) post.attachments = [];
  if (post.image && !post.attachments.some(a => a.url === post.image)) {
    post.attachments.unshift({
      url: post.image,
      name: "image",
      mimetype: "image/*",
      size: 0,
      kind: "image"
    });
  }
}

function detectKind(mimetype = "", filename = "") {
  const mt = String(mimetype).toLowerCase();
  const fn = String(filename).toLowerCase();

  if (mt.startsWith("image/")) return "image";
  if (mt.startsWith("video/")) return "video";
  if (mt.startsWith("audio/")) return "audio";

  // simple fallback by extension
  if (fn.match(/\.(png|jpg|jpeg|gif|webp)$/)) return "image";
  if (fn.match(/\.(mp4|webm|mov|mkv)$/)) return "video";
  if (fn.match(/\.(mp3|wav|ogg|m4a|aac|flac)$/)) return "audio";

  return "file";
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

// Safe feed (NO IP data)
app.get('/api/posts', (req, res) => {
  const safe = posts.map(p => {
    normalizeAttachmentsFromLegacy(p);
    return {
      id: p.id,
      title: p.title,
      text: p.text,
      image: p.image || null, // keep legacy field
      attachments: (p.attachments || []).map(a => ({
        url: a.url,
        name: a.name,
        mimetype: a.mimetype,
        size: a.size,
        kind: a.kind
      })),
      date: p.date,
      likes: p.likes,
      dislikes: p.dislikes,
      comments: p.comments.length
    };
  });
  res.json(safe.reverse());
});

// Safe detail view (NO IP data)
app.get('/api/posts/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Post not found" });

  normalizeAttachmentsFromLegacy(post);

  return res.json({
    id: post.id,
    title: post.title,
    text: post.text,
    image: post.image || null, // keep legacy field
    attachments: (post.attachments || []).map(a => ({
      url: a.url,
      name: a.name,
      mimetype: a.mimetype,
      size: a.size,
      kind: a.kind
    })),
    date: post.date,
    likes: post.likes,
    dislikes: post.dislikes,
    comments: post.comments.map(c => ({ id: c.id, text: c.text, date: c.date }))
  });
});

// -------------------- CREATE POST (MULTI FILES) --------------------
// Frontend sends: files[] (many)
app.post('/api/upload', requireNotBannedAndNotMaintenance, upload.array('files', 50), (req, res) => {
  try {
    const title = (req.body.title || '').toString();
    const text = (req.body.text || '').toString();

    if (filter.isProfane(title) || filter.isProfane(text)) {
      return res.status(400).json({ error: 'Profanity detected.' });
    }

    const ip = getClientIp(req);
    const ua = req.headers['user-agent'] || '';
    const createdAt = Date.now();

    const files = Array.isArray(req.files) ? req.files : [];
    const attachments = files.map(f => ({
      url: `/uploads/${f.filename}`,
      name: f.originalname || f.filename,
      mimetype: f.mimetype || "application/octet-stream",
      size: f.size || 0,
      kind: detectKind(f.mimetype, f.originalname)
    }));

    const newPost = {
      id: createdAt,
      title,
      text,

      // keep legacy field (first image if any)
      image: (() => {
        const firstImg = attachments.find(a => a.kind === "image");
        return firstImg ? firstImg.url : null;
      })(),

      attachments,
      date: nowStr(),

      // interactions
      likes: 0,
      dislikes: 0,
      comments: [],

      // per-IP voting
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
      attachments: newPost.attachments,
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

  if (post.likedBy.has(ip)) return res.status(400).json({ error: "Already liked" });

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

// -------------------- COMMENTS (store admin-only safety data) --------------------
app.post('/api/posts/:id/comment', requireNotBannedAndNotMaintenance, (req, res) => {
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Post not found" });

  const text = (req.body && req.body.text ? String(req.body.text) : "").trim();
  if (!text) return res.status(400).json({ error: "Empty comment" });
  if (filter.isProfane(text)) return res.status(400).json({ error: "Profanity detected." });

  const ip = getClientIp(req);
  const ua = req.headers['user-agent'] || '';

  const comment = {
    id: Date.now() + Math.floor(Math.random() * 100000),
    text,
    date: nowStr(),

    // admin-only:
    commenterIp: ip,
    commenterUa: ua,
    commenterHeaders: {
      acceptLanguage: req.headers['accept-language'] || '',
      cfRay: req.headers['cf-ray'] || '',
      cfIpcountry: req.headers['cf-ipcountry'] || ''
    }
  };

  post.comments.push(comment);
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
  const out = posts.slice().reverse().map(p => {
    normalizeAttachmentsFromLegacy(p);
    return {
      id: p.id,
      title: p.title,
      text: p.text,
      image: p.image || null,
      attachments: (p.attachments || []).map(a => ({ ...a })),
      date: p.date,
      likes: p.likes,
      dislikes: p.dislikes,
      comments: p.comments,
      ownerIp: p.ownerIp
    };
  });
  res.json(out);
});

app.delete('/api/admin/posts/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const before = posts.length;
  posts = posts.filter(p => p.id !== id);
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

// -------------------- OPTIONAL GEO LOOKUP (IPINFO_TOKEN) --------------------
async function ipInfoLookup(ip) {
  const token = process.env.IPINFO_TOKEN;
  if (!token) return null;

  try {
    const resp = await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}?token=${encodeURIComponent(token)}`, {
      headers: { 'Accept': 'application/json' }
    });
    if (!resp.ok) return null;
    const data = await resp.json();
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

// -------------------- ADMIN SAFETY: POST DETAILS --------------------
app.get('/api/admin/posts/:id/details', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Post not found" });

  const ua = post.ownerUa || "";
  const parsed = new UAParser(ua).getResult();
  const ip = post.ownerIp || "unknown";
  const geo = await ipInfoLookup(ip);

  return res.json({
    type: "post",
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
      acceptLanguage: post.ownerHeaders?.acceptLanguage || null,
      cfRay: post.ownerHeaders?.cfRay || null,
      cfIpCountry: post.ownerHeaders?.cfIpcountry || null,
      referer: post.ownerHeaders?.referer || null
    },
    geo: geo || { city: null, region: null, country: null, ispOrg: null, timezone: null },
    notes: { privacy: "City/ISP require IPINFO_TOKEN. Otherwise null." }
  });
});

// -------------------- ADMIN SAFETY: COMMENT DETAILS (NEW) --------------------
app.get('/api/admin/posts/:postId/comments/:commentId/details', requireAdmin, async (req, res) => {
  const postId = parseInt(req.params.postId);
  const commentId = parseInt(req.params.commentId);

  const post = posts.find(p => p.id === postId);
  if (!post) return res.status(404).json({ error: "Post not found" });

  const comment = (post.comments || []).find(c => c.id === commentId);
  if (!comment) return res.status(404).json({ error: "Comment not found" });

  const ua = comment.commenterUa || "";
  const parsed = new UAParser(ua).getResult();
  const ip = comment.commenterIp || "unknown";
  const geo = await ipInfoLookup(ip);

  return res.json({
    type: "comment",
    postId,
    commentId,
    createdAt: null,
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
      acceptLanguage: comment.commenterHeaders?.acceptLanguage || null,
      cfRay: comment.commenterHeaders?.cfRay || null,
      cfIpCountry: comment.commenterHeaders?.cfIpcountry || null
    },
    geo: geo || { city: null, region: null, country: null, ispOrg: null, timezone: null },
    notes: { privacy: "Comment safety is admin-only. City/ISP require IPINFO_TOKEN." }
  });
});

app.listen(port, () => console.log(`Server running on ${port}`));
