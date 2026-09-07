// YOUR PASSWORDS — EDIT THESE!
process.env.ADMIN_PASSWORD = "Giraffe";
process.env.SESSION_SECRET = "Giraffe";

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

if (!fs.existsSync('./data')) fs.mkdirSync('./data');
const app = express();
const PORT = process.env.PORT || 3000;

const mainDB = new Database('./data/main.db');
const adminDB = new Database('./data/admin.db');

// CREATE TABLES
mainDB.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS user_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    data_type TEXT NOT NULL,
    data_json TEXT NOT NULL,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, data_type)
  );
`);

adminDB.exec(`
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    message TEXT NOT NULL,
    read INTEGER DEFAULT 0,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS master_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    label TEXT NOT NULL,
    content TEXT NOT NULL,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// MIDDLEWARE
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// EMAIL VALIDATOR
function isValidEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

// AUTH GUARD
function requireAuth(req, res, next) {
  const publicPaths = ['/login.html', '/api/login', '/api/signup', '/api/me'];
  if (publicPaths.some(p => req.path === p || req.path.startsWith('/api/') && publicPaths.includes(req.path))) {
    return next();
  }
  if (!req.session.user) return res.redirect('/login.html');
  next();
}
app.use(requireAuth);

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null, isAdmin: !!req.session.isAdmin });
});

// SIGNUP — WITH EMAIL & NOTIFICATION
app.post('/api/signup', (req, res) => {
  const { username, email, password } = req.body;
  
  // VALIDATIONS
  if (!username || username.length < 2) return res.json({ error: 'Username needs at least 2 characters' });
  if (!email || !isValidEmail(email)) return res.json({ error: 'Enter a VALID email address (e.g. name@gmail.com)' });
  if (!password || password.length < 6) return res.json({ error: 'Password needs at least 6 characters' });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const stmt = mainDB.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
    const result = stmt.run(username.toLowerCase().trim(), email.toLowerCase().trim(), hash);
    
    // 🔔 NOTIFY ADMIN — SOMETHING ACTUALLY HAPPENS!
    adminDB.prepare(`INSERT INTO notifications (type, message) VALUES ('signup', ?)`)
      .run(`🆕 NEW USER: ${username} | Email: ${email} | Joined: ${new Date().toLocaleString()}`);
    
    console.log(`✅ NEW SIGNUP — User: ${username} | Email: ${email}`);
    req.session.user = { id: result.lastInsertRowid, username, email };
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      if (err.message.includes('email')) res.json({ error: 'That email is already registered' });
      else res.json({ error: 'That username is already taken' });
    } else {
      res.json({ error: 'Signup failed — try again' });
    }
  }
});

// LOGIN
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = mainDB.prepare('SELECT * FROM users WHERE username = ? OR email = ?')
    .get(username.toLowerCase().trim(), username.toLowerCase().trim());
  
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.json({ error: 'Wrong username/email or password' });
  }
  
  req.session.user = { id: user.id, username: user.username, email: user.email };
  res.json({ success: true, user: req.session.user });
});

app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// SAVE/LOAD USER DATA
app.post('/api/user/save', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const { dataType, data } = req.body;
  mainDB.prepare(`INSERT OR REPLACE INTO user_data (user_id, data_type, data_json, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`)
    .run(req.session.user.id, dataType, JSON.stringify(data));
  res.json({ success: true });
});

app.get('/api/user/load/:dataType', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const row = mainDB.prepare('SELECT data_json FROM user_data WHERE user_id = ? AND data_type = ?')
    .get(req.session.user.id, req.params.dataType);
  res.json({ data: row ? JSON.parse(row.data_json) : null });
});

// ADMIN LOGIN & DATA
app.post('/api/admin/login', (req, res) => {
  if (req.body.password === process.env.ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    res.json({ success: true });
  } else {
    res.json({ success: false, error: 'Wrong master password' });
  }
});

app.get('/api/admin/alldata', (req, res) => {
  if (!req.session.isAdmin) return res.json({ error: 'Unauthorized' });
  const users = mainDB.prepare('SELECT id, username, email, created_at FROM users ORDER BY id DESC').all();
  const allUserData = mainDB.prepare(`SELECT ud.*, u.username, u.email FROM user_data ud JOIN users u ON ud.user_id = u.id ORDER BY ud.updated_at DESC`).all();
  const notifications = adminDB.prepare('SELECT * FROM notifications ORDER BY timestamp DESC LIMIT 50').all();
  const masterRecords = adminDB.prepare('SELECT * FROM master_records ORDER BY created_at DESC').all();
  res.json({ users, allUserData, notifications, masterRecords });
});

app.post('/api/admin/notifications/read', (req, res) => {
  if (!req.session.isAdmin) return res.json({ error: 'Unauthorized' });
  adminDB.prepare('UPDATE notifications SET read = 1').run();
  res.json({ success: true });
});

app.post('/api/admin/master/add', (req, res) => {
  if (!req.session.isAdmin) return res.json({ error: 'Unauthorized' });
  const { category, label, content, notes } = req.body;
  adminDB.prepare('INSERT INTO master_records (category, label, content, notes) VALUES (?, ?, ?, ?)')
    .run(category, label, content, notes);
  res.json({ success: true });
});

console.log('🚀 Server running with EMAIL & URL support!');
app.listen(PORT);
