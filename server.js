const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Filter = require('bad-words');

const app = express();
const filter = new Filter();
const port = 3000;

app.set('trust proxy', true); // IMPORTANT for IP behind tunnel/proxy

app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// ----- Uploads folder -----
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// ----- Multer -----
const storage = multer.diskStorage({
  destination: uploadsDir,
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

// ----- Auth -----
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";
const ADMIN_TOKEN = "admin_token_active";

function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: "Admin only" });
  next();
}

// ----- IP helpers -----
function getClientIp(req) {
  // prefer Cloudflare header if present
  const cf = req.headers["cf-connecting-ip"];
  if (cf) return String(cf);

  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();

  const ip = req.ip || req.socket?.remoteAddress || "";
  return String(ip).replace("::ffff:", "");
}

// ----- In-memory "database" -----
let posts = [];       // {id,title,text,image,date, ownerIp, likesByIp:Set, dislikesByIp:Set, comments:[...]}
let reports = [];     // {id, postId, reason, message, reporterIp, timestamp}
let bannedIps = new Set();
let maintenanceMode = false;

// ----- Utilities to sanitize data for normal users -----
function publicPostSummary(post) {
  return {
    id: post.id,
    title: post.title,
    text: post.text,
    image: post.image,
    date: post.date,
    likes: post.likesByIp.size,
    dislikes: post.dislikesByIp.size,
    comments: post.comments.length
  };
}

function publicPostDetail(post) {
  return {
    id: post.id,
    title: post.title,
    text: post.text,
    image: post.image,
    date: post.date,
    likes: post.likesByIp.size,
    dislikes: post.dislikesByIp.size,
    comments: post.comments.map(c => ({
      id: c.id,
      text: c.text,
      date: c.date
    }))
  };
}

// ----- Restrictions for normal users during maintenance / ban -----
function blockIfBannedOrMaintenance(req, res, next) {
  const ip = getClientIp(req);

  // Admin bypass: if valid admin token, allow
  const token = req.headers["x-admin-token"];
  const isAdmin = token === ADMIN_TOKEN;

  if (!isAdmin && maintenanceMode) {
    return res.status(503).json({ error: "Maintenance mode" });
  }
  if (!isAdmin && bannedIps.has(ip)) {
    return res.status(403).json({ error: "You are banned." });
  }
  next();
}

// ----- Basic endpoints -----
app.get('/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.get('/api/status', (req, res) => {
  res.json({ maintenance: maintenanceMode });
});

// ----- Login -----
app.post('/api/login', (req, res) => {
  const { password } = req.body || {};
  if (password === ADMIN_PASSWORD) {
    res.json({ success: true, token: ADMIN_TOKEN });
  } else {
    res.status(401).json({ error: "Wrong password" });
  }
});

app.get('/api/admin/status', requireAdmin, (req, res) => {
  res.json({ ok: true, maintenance: maintenanceMode, bannedCount: bannedIps.size, reportsCount: reports.length });
});

// ----- Posts (public) -----
app.get('/api/posts', (req, res) => {
  // newest first without mutating
  const list = [...posts].reverse().map(publicPostSummary);
  res.json(list);
});

app.get('/api/posts/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Not found" });
  res.json(publicPostDetail(post));
});

// ----- Upload post -----
app.post('/api/upload', blockIfBannedOrMaintenance, upload.single('image'), (req, res) => {
  try {
    const ip = getClientIp(req);
    const title = req.body.title || '';
    const text = req.body.text || '';

    if (filter.isProfane(title) || filter.isProfane(text)) {
      return res.status(400).json({ error: 'Profanity detected.' });
    }

    const newPost = {
      id: Date.now(),
      title,
      text,
      image: req.file ? `/uploads/${req.file.filename}` : null,
      date: new Date().toLocaleString(),
      ownerIp: ip,
      likesByIp: new Set(),
      dislikesByIp: new Set(),
      comments: []
    };

    posts.push(newPost);
    res.status(201).json(publicPostSummary(newPost));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ----- Likes / Dislikes -----
app.post('/api/posts/:id/like', blockIfBannedOrMaintenance, (req, res) => {
  const ip = getClientIp(req);
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Not found" });

  // toggle like; remove dislike if present
  if (post.likesByIp.has(ip)) {
    post.likesByIp.delete(ip);
  } else {
    post.likesByIp.add(ip);
    post.dislikesByIp.delete(ip);
  }

  res.json({ likes: post.likesByIp.size, dislikes: post.dislikesByIp.size });
});

app.post('/api/posts/:id/dislike', blockIfBannedOrMaintenance, (req, res) => {
  const ip = getClientIp(req);
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Not found" });

  // toggle dislike; remove like if present
  if (post.dislikesByIp.has(ip)) {
    post.dislikesByIp.delete(ip);
  } else {
    post.dislikesByIp.add(ip);
    post.likesByIp.delete(ip);
  }

  res.json({ likes: post.likesByIp.size, dislikes: post.dislikesByIp.size });
});

// ----- Comments -----
app.post('/api/posts/:id/comment', blockIfBannedOrMaintenance, (req, res) => {
  const ip = getClientIp(req);
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Not found" });

  const text = (req.body?.text || "").toString().trim();
  if (!text) return res.status(400).json({ error: "Comment required" });

  if (filter.isProfane(text)) {
    return res.status(400).json({ error: "Profanity detected." });
  }

  const c = {
    id: Date.now(),
    text,
    date: new Date().toLocaleString(),
    ip // stored for admin-only but not shown to users
  };

  post.comments.push(c);

  res.status(201).json({
    comments: post.comments.length,
    comment: { id: c.id, text: c.text, date: c.date }
  });
});

// ----- Reports -----
app.post('/api/posts/:id/report', blockIfBannedOrMaintenance, (req, res) => {
  const reporterIp = getClientIp(req);
  const id = parseInt(req.params.id);
  const post = posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: "Not found" });

  const reason = (req.body?.reason || "").toString().trim();
  const message = (req.body?.message || "").toString().trim();

  const allowedReasons = new Set([
    "Spam",
    "Hate or abuse",
    "Illegal content",
    "Harassment",
    "Misinformation",
    "Something else"
  ]);

  if (!allowedReasons.has(reason)) {
    return res.status(400).json({ error: "Invalid reason" });
  }

  if (reason === "Something else" && message.length < 3) {
    return res.status(400).json({ error: "Please explain (Something else)" });
  }

  const r = {
    id: Date.now(),
    postId: post.id,
    reason,
    message: message || null,
    reporterIp,
    timestamp: new Date().toISOString()
  };

  reports.push(r);
  res.status(201).json({ success: true });
});

// ----- Existing delete route (kept) now admin-only -----
app.delete('/api/posts/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);

  // remove post
  posts = posts.filter(p => p.id !== id);

  // remove reports for that post
  reports = reports.filter(r => r.postId !== id);

  res.json({ success: true });
});

// =========================
// ===== ADMIN ROUTES ======
// =========================

// View all posts (with owner IP, commenter IP hidden from normal users)
app.get('/api/admin/posts', requireAdmin, (req, res) => {
  const out = [...posts].reverse().map(p => ({
    id: p.id,
    title: p.title,
    text: p.text,
    image: p.image,
    date: p.date,
    ownerIp: p.ownerIp,
    likes: p.likesByIp.size,
    dislikes: p.dislikesByIp.size,
    comments: p.comments.map(c => ({
      id: c.id,
      text: c.text,
      date: c.date,
      ip: c.ip
    }))
  }));
  res.json(out);
});

// Delete any post (admin)
app.delete('/api/admin/posts/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  posts = posts.filter(p => p.id !== id);
  reports = reports.filter(r => r.postId !== id);
  res.json({ success: true });
});

// Reports view (admin)
app.get('/api/admin/reports', requireAdmin, (req, res) => {
  const out = reports
    .slice()
    .reverse()
    .map(r => {
      const post = posts.find(p => p.id === r.postId);
      return {
        id: r.id,
        postId: r.postId,
        reason: r.reason,
        message: r.message,
        reporterIp: r.reporterIp,
        timestamp: r.timestamp,
        post: post ? {
          id: post.id,
          title: post.title,
          text: post.text,
          image: post.image,
          date: post.date,
          ownerIp: post.ownerIp
        } : null
      };
    });

  res.json(out);
});

// Ignore report
app.post('/api/admin/reports/:id/ignore', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  reports = reports.filter(r => r.id !== id);
  res.json({ success: true });
});

// Ban / unban
app.get('/api/admin/bans', requireAdmin, (req, res) => {
  res.json({ banned: Array.from(bannedIps) });
});

app.post('/api/admin/ban', requireAdmin, (req, res) => {
  const ip = (req.body?.ip || "").toString().trim();
  if (!ip) return res.status(400).json({ error: "IP required" });
  bannedIps.add(ip);
  res.json({ success: true, banned: Array.from(bannedIps) });
});

app.post('/api/admin/unban', requireAdmin, (req, res) => {
  const ip = (req.body?.ip || "").toString().trim();
  if (!ip) return res.status(400).json({ error: "IP required" });
  bannedIps.delete(ip);
  res.json({ success: true, banned: Array.from(bannedIps) });
});

// Maintenance mode toggle
app.post('/api/admin/maintenance', requireAdmin, (req, res) => {
  const enabled = !!req.body?.enabled;
  maintenanceMode = enabled;
  res.json({ success: true, maintenance: maintenanceMode });
});

// ----- Multer/global errors -----
app.use((err, req, res, next) => {
  if (err) return res.status(400).json({ error: err.message || "Error" });
  next();
});

app.listen(port, () => console.log(`Server running on ${port}`));
