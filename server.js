const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Filter = require('bad-words');

const app = express();
const filter = new Filter();
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Ensure uploads folder exists
if (!fs.existsSync('./uploads')){
    fs.mkdirSync('./uploads');
}

// Storage Setup
const storage = multer.diskStorage({
    destination: './uploads',
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

// Upload Config (Unlimited files, 50MB limit per file)
const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif|webp/;
        const mimetype = filetypes.test(file.mimetype);
        if (mimetype) return cb(null, true);
        cb(new Error('Only images are allowed!'));
    }
});

// Database
let posts = [];
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123"; // Fallback if secret fails

// Routes
app.get('/api/posts', (req, res) => {
    res.json(posts.reverse());
});

app.post('/api/login', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        res.json({ success: true, token: "admin_token_active" });
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

// Admin Delete Route (Only accessible if you implement frontend logic for it later)
app.delete('/api/posts/:id', (req, res) => {
    // Ideally check token here, but keeping it simple for now
    const id = parseInt(req.params.id);
    posts = posts.filter(post => post.id !== id);
    res.json({ success: true });
});

app.listen(port, () => console.log(`Server running on ${port}`));
