const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const session = require('express-session');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'scl90-secret-key-2024';

// Database
const db = new sqlite3.Database('./scl90.db');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Initialize database
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_admin INTEGER DEFAULT 0
    )`);

    // Assessment results table
    db.run(`CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        total_score REAL,
        average_score REAL,
        dimensions TEXT,
        answers TEXT,
        completed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
});

// Auth middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: '请先登录' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: '登录已过期' });
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (!req.user.is_admin) {
        return res.status(403).json({ error: '无权访问' });
    }
    next();
};

// Routes

// Register
app.post('/api/register', async (req, res) => {
    const { username, password, email } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: '用户名和密码必填' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            [username, hashedPassword, email],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: '用户名已存在' });
                    }
                    return res.status(500).json({ error: '注册失败' });
                }
                res.json({ message: '注册成功', userId: this.lastID });
            }
        );
    } catch (error) {
        res.status(500).json({ error: '注册失败' });
    }
});

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: '用户不存在' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: '密码错误' });
        }
        
        const token = jwt.sign(
            { id: user.id, username: user.username, is_admin: user.is_admin },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ token, username: user.username, is_admin: user.is_admin });
    });
});

// Save assessment result
app.post('/api/results', authenticateToken, (req, res) => {
    const { totalScore, averageScore, dimensions, answers } = req.body;
    
    db.run(`INSERT INTO results (user_id, total_score, average_score, dimensions, answers) 
            VALUES (?, ?, ?, ?, ?)`,
        [req.user.id, totalScore, averageScore, JSON.stringify(dimensions), JSON.stringify(answers)],
        function(err) {
            if (err) return res.status(500).json({ error: '保存失败' });
            res.json({ message: '保存成功', resultId: this.lastID });
        }
    );
});

// Get user's results
app.get('/api/results', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM results WHERE user_id = ? ORDER BY completed_at DESC`,
        [req.user.id],
        (err, rows) => {
            if (err) return res.status(500).json({ error: '获取失败' });
            res.json(rows.map(row => ({
                ...row,
                dimensions: JSON.parse(row.dimensions || '{}'),
                answers: JSON.parse(row.answers || '[]')
            })));
        }
    );
});

// Admin: Get all results
app.get('/api/admin/results', authenticateToken, isAdmin, (req, res) => {
    db.all(`SELECT r.*, u.username, u.email 
            FROM results r 
            LEFT JOIN users u ON r.user_id = u.id 
            ORDER BY r.completed_at DESC`,
        (err, rows) => {
            if (err) return res.status(500).json({ error: '获取失败' });
            res.json(rows.map(row => ({
                ...row,
                dimensions: JSON.parse(row.dimensions || '{}'),
                answers: JSON.parse(row.answers || '[]')
            })));
        }
    );
});

// Admin: Get all users
app.get('/api/admin/users', authenticateToken, isAdmin, (req, res) => {
    db.all(`SELECT id, username, email, created_at, is_admin 
            FROM users ORDER BY created_at DESC`,
        (err, rows) => {
            if (err) return res.status(500).json({ error: '获取失败' });
            res.json(rows);
        }
    );
});

// Admin: Create admin user
app.post('/api/admin/create', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: '创建失败' });
        db.run('INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)',
            [username, hash],
            function(err) {
                if (err) return res.status(500).json({ error: '用户名已存在' });
                res.json({ message: '管理员创建成功' });
            }
        );
    });
});

// Serve frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    const os = require('os');
    const network = os.networkInterfaces();
    let localIP = 'localhost';
    
    for (const interfaces in network) {
        for (const details in network[interfaces]) {
            if (network[interfaces][details].family === 'IPv4' && !network[interfaces][details].internal) {
                localIP = network[interfaces][details].address;
                break;
            }
        }
    }
    
    console.log(`Server running!`);
    console.log(`本机访问: http://localhost:${PORT}`);
    console.log(`局域网访问: http://${localIP}:${PORT}`);
    console.log(`Admin panel: http://${localIP}:${PORT}/admin.html`);
});
