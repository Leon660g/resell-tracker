process.env.ADMIN_PASSWORD = "Giraffe";
process.env.SESSION_SECRET = "ResellTrackerSecret2026";

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

// ========== DATABASE SETUP ==========
const mainDB = new Database('./data/main.db');
const adminDB = new Database('./data/admin.db');

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
  CREATE TABLE IF NOT EXISTS buyers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    contact TEXT,
    email TEXT,
    notes TEXT,
    total_spent REAL DEFAULT 0,
    purchase_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    buyer_id INTEGER,
    item_name TEXT NOT NULL,
    buy_price REAL DEFAULT 0,
    sold_price REAL DEFAULT 0,
    shipping_cost REAL DEFAULT 0,
    fees REAL DEFAULT 0,
    status TEXT DEFAULT 'pending',
    payment_date TEXT,
    ship_date TEXT,
    delivered_date TEXT,
    due_date TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (buyer_id) REFERENCES buyers(id) ON DELETE SET NULL
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
`);

// ========== MIDDLEWARE ==========
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function requireAuth(req, res, next) {
  const publicPaths = [
    '/login.html', 
    '/api/login', 
    '/api/signup', 
    '/api/me',
    '/api/admin/login',      // ← ADD THIS
    '/api/admin/alldata',    // ← ADD THIS
    '/api/admin/notifications/read'  // ← ADD THIS
  ];
  if (publicPaths.some(p => req.path.startsWith(p))) {
    return next();
  }
  if (!req.session.user) return res.redirect('/login.html');
  next();
}
}
app.use(requireAuth);

// ========== BASIC AUTH ==========
app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null, isAdmin: !!req.session.isAdmin });
});

app.post('/api/signup', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || username.length < 2) return res.json({ error: 'Username needs at least 2 characters' });
  if (!email || !isValidEmail(email)) return res.json({ error: 'Enter a valid email address' });
  if (!password || password.length < 6) return res.json({ error: 'Password needs at least 6 characters' });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const stmt = mainDB.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
    const result = stmt.run(username.toLowerCase().trim(), email.toLowerCase().trim(), hash);
    
    adminDB.prepare(`INSERT INTO notifications (type, message) VALUES ('signup', ?)`)
      .run(`🆕 NEW USER: ${username} | Email: ${email} | Joined: ${new Date().toLocaleString()}`);
    
    req.session.user = { id: result.lastInsertRowid, username, email };
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      res.json({ error: err.message.includes('email') ? 'Email already registered' : 'Username already taken' });
    } else res.json({ error: 'Signup failed' });
  }
});

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

// ========== USER DATA SAVE/LOAD ==========
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

// ========== BUYER CRM API ==========
app.get('/api/buyers/list', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const buyers = mainDB.prepare('SELECT * FROM buyers WHERE user_id = ? ORDER BY total_spent DESC, created_at DESC')
    .all(req.session.user.id);
  res.json({ buyers });
});

app.post('/api/buyers/add', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const { name, contact, email, notes, status } = req.body;
  if (!name) return res.json({ error: 'Buyer name is required' });
  const result = mainDB.prepare(`INSERT INTO buyers (user_id, name, contact, email, notes, status) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(req.session.user.id, name, contact || '', email || '', notes || '', status || 'active');
  res.json({ success: true, buyerId: result.lastInsertRowid });
});

app.post('/api/buyers/delete', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  mainDB.prepare('DELETE FROM buyers WHERE id = ? AND user_id = ?').run(req.body.id, req.session.user.id);
  res.json({ success: true });
});

// ========== TRANSACTIONS / SALES API ==========
app.get('/api/transactions/list', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const tx = mainDB.prepare(`SELECT t.*, b.name as buyer_name FROM transactions t LEFT JOIN buyers b ON t.buyer_id = b.id WHERE t.user_id = ? ORDER BY created_at DESC`)
    .all(req.session.user.id);
  tx.forEach(t => {
    t.profit = (t.sold_price || 0) - (t.buy_price || 0) - (t.shipping_cost || 0) - (t.fees || 0);
  });
  res.json({ transactions: tx });
});

app.post('/api/transactions/add', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const { buyer_id, item_name, buy_price, sold_price, shipping_cost, fees, status, due_date, notes } = req.body;
  const result = mainDB.prepare(`INSERT INTO transactions (user_id, buyer_id, item_name, buy_price, sold_price, shipping_cost, fees, status, due_date, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(req.session.user.id, buyer_id || null, item_name, buy_price || 0, sold_price || 0, shipping_cost || 0, fees || 0, status || 'pending', due_date || null, notes || '');
  res.json({ success: true, txId: result.lastInsertRowid });
});

// ========== ADMIN PANEL API — SIMPLE & RELIABLE ==========
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
  const notifications = adminDB.prepare('SELECT * FROM notifications ORDER BY timestamp DESC LIMIT 50').all();
  res.json({ users, notifications });
});

app.post('/api/admin/notifications/read', (req, res) => {
  if (!req.session.isAdmin) return res.json({ error: 'Unauthorized' });
  adminDB.prepare('UPDATE notifications SET read = 1').run();
  res.json({ success: true });
});

console.log('🚀 RR Resell Tracker — FULL SYSTEM ONLINE');
// ========== ADMIN PANEL API ENDPOINTS ==========
app.post('/api/admin/login', (req, res) => {
  if (req.body.password === process.env.ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    res.json({ success: true });
  } else {
    res.json({ success: false, error: 'Wrong password' });
  }
});

app.get('/api/admin/alldata', (req, res) => {
  if (!req.session.isAdmin) return res.json({ error: 'Unauthorized' });
  const users = mainDB.prepare('SELECT id, username, email, created_at FROM users ORDER BY id DESC').all();
  const notifications = adminDB.prepare('SELECT * FROM notifications ORDER BY timestamp DESC LIMIT 50').all();
  res.json({ users, notifications });
});

app.post('/api/admin/notifications/read', (req, res) => {
  if (!req.session.isAdmin) return res.json({ error: 'Unauthorized' });
  adminDB.prepare('UPDATE notifications SET read = 1').run();
  res.json({ success: true });
});

// ========== THIS MUST BE THE VERY LAST LINE ==========
console.log('🚀 RR Resell Tracker — FULL SYSTEM ONLINE');
app.listen(PORT);
