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
app.use(express.static('public')); // Serve the frontend
app.use('/uploads', express.static('uploads')); // Serve uploaded images

// Storage Setup (Save files to 'uploads' folder)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = './uploads';
        if (!fs.existsSync(dir)){
            fs.mkdirSync(dir);
        }
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Unique filename
    }
});

// Upload Restrictions (Images only, max 5MB)
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif|webp/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Only images are allowed!'));
    }
});

// In-memory Database (Wipes on restart)
let posts = [];

// API Routes
app.get('/api/posts', (req, res) => {
    res.json(posts.reverse()); // Send newest first
});

app.post('/api/upload', upload.single('image'), (req, res) => {
    try {
        const text = req.body.text || '';
        
        // Content Moderation
        if (filter.isProfane(text)) {
            return res.status(400).json({ error: 'Please keep it clean. No bad language.' });
        }

        const newPost = {
            id: Date.now(),
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

app.listen(port, () => {
    console.log(`DeadChats Files running on port ${port}`);
});
