const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Filter = require('bad-words');

const app = express();
const filter = new Filter();
const port = 3000;

app.use(express.json());

// ✅ Keep your static setup (same feature)
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// ✅ Ensure uploads directory exists (more robust)
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// ✅ Multer config (same feature, more robust path usage)
const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif|webp/;
    const mimetype = filetypes.test(file.mimetype);
    if (mimetype) return cb(null, true);
    cb(new Error('Only images are allowed!'));
  }
});

// ✅ Your posts in memory (same feature)
let posts = [];

// ✅ Your admin password env (same feature)
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

// ✅ Simple admin token (same behavior you already returned, now actually used)
const ADMIN_TOKEN = "admin_token_active";

// ✅ Helper middleware to protect admin routes
function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: "Admin only" });
  next();
}

// ✅ Health endpoint (doesn’t remove anything; helps debugging)
app.get('/health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// ✅ FIX: posts.reverse() was mutating your array each request
app.get('/api/posts', (req, res) => {
  res.json([...posts].reverse());
});

app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    res.json({ success: true, token: ADMIN_TOKEN });
  } else {
    res.status(401).json({ error: "Wrong password" });
  }
});

app.post('/api/upload', upload.single('image'), (req, res) => {
  try {
    const title = req.body.title || '';
    const text = req.body.text || '';

    if (filter.isProfane(title) || filter.isProfane(text)) {
      return res.status(400).json({ error: 'Profanity detected.' });
    }

    const newPost = {
      id: Date.now(),
      title: title,
      text: text,
      image: req.file ? `/uploads/${req.file.filename}` : null,
      date: new Date().toLocaleString()
    };

    posts.push(newPost);
    res.status(201).json(newPost);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ✅ FIX/SECURITY: delete was open to everyone, now admin-only
app.delete('/api/posts/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  posts = posts.filter(post => post.id !== id);
  res.json({ success: true });
});

// ✅ Better error response for multer errors (still keeps your behavior)
app.use((err, req, res, next) => {
  if (err) return res.status(400).json({ error: err.message || "Upload error" });
  next();
});

app.listen(port, () => console.log(`Server running on ${port}`));
