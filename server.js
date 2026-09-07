process.env.ADMIN_PASSWORD = "Giraffe";
process.env.SESSION_SECRET = "ResellTrackerSecret2026";

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

if (!fs.existsSync('./data')) fs.mkdirSync('./data');
if (!fs.existsSync('./public/uploads')) fs.mkdirSync('./public/uploads', { recursive: true });

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
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS user_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    currency TEXT DEFAULT '£',
    dark_mode INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
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
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    buyer_id INTEGER,
    item_name TEXT NOT NULL,
    item_image TEXT,
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
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(buyer_id) REFERENCES buyers(id) ON DELETE SET NULL
  );
`);

adminDB.exec(`
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    message TEXT NOT NULL,
    read INTEGER DEFAULT 0,
    timestamp TEXT DEFAULT (datetime('now'))
  );
`);

// ========== MIDDLEWARE ==========
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// ✅ PERMANENT LOGIN — 100 DAYS
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 100 * 24 * 60 * 60 * 1000
  }
}));

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function cleanStr(str) { return str ? str.trim().substring(0, 500) : ''; }

// ✅ PUBLIC ROUTES
function requireAuth(req, res, next) {
  const publicPaths = [
    '/login.html', '/api/login', '/api/signup', '/api/me',
    '/api/admin/login', '/api/admin/alldata'
  ];
  if (publicPaths.some(p => req.path.startsWith(p))) return next();
  if (!req.session.user) return res.redirect('/login.html');
  next();
}
app.use(requireAuth);

// ========== 📷 UPLOAD IMAGE ROUTE ==========
app.post('/api/upload-image', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const { base64, name } = req.body;
  if (!base64) return res.json({ error: 'No image data' });

  const ext = name?.endsWith('.png') ? '.png' : name?.endsWith('.gif') ? '.gif' : '.jpg';
  const filename = `${crypto.randomBytes(16).toString('hex')}${ext}`;
  const filepath = path.join(__dirname, 'public', 'uploads', filename);
  
  const data = base64.replace(/^data:image\/\w+;base64,/, '');
  fs.writeFileSync(filepath, data, 'base64');
  
  res.json({ success: true, url: `/uploads/${filename}` });
});

// ========== 🎨 AI IMAGE GENERATOR ROUTE ==========
app.post('/api/generate-image', async (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const { prompt } = req.body;
  if (!prompt || prompt.length < 3) return res.json({ error: 'Enter a description first' });

  try {
    const cleanPrompt = encodeURIComponent(prompt + ', professional product photo, white background, high quality, 4k, sharp focus');
    const imageUrl = `https://image.pollinations.ai/prompt/${cleanPrompt}?width=512&height=512&nologo=true&seed=${Date.now()}`;
    
    res.json({ 
      success: true, 
      imageUrl: imageUrl,
      prompt: prompt
    });
  } catch (err) {
    console.error('Image Gen Error:', err);
    res.json({ error: '❌ Failed to generate image — try again' });
  }
});

// ========== USER STATUS ==========
app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null, isAdmin: !!req.session.isAdmin });
});

// ========== SIGNUP ==========
app.post('/api/signup', (req, res) => {
  let { username, email, password } = req.body;
  username = cleanStr(username); email = cleanStr(email).toLowerCase();
  
  if (!username || username.length < 2) return res.json({ error: 'Username needs at least 2 characters' });
  if (!email || !isValidEmail(email)) return res.json({ error: 'Enter a valid email address' });
  if (!password || password.length < 6) return res.json({ error: 'Password needs at least 6 characters' });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const stmt = mainDB.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
    const result = stmt.run(username.toLowerCase(), email, hash);
    
    mainDB.prepare('INSERT INTO user_settings (user_id) VALUES (?)').run(result.lastInsertRowid);
    
    adminDB.prepare('INSERT INTO notifications (type, message) VALUES (?, ?)')
      .run('signup', `🆕 New user: ${username} — ${email}`);

    req.session.user = { id: result.lastInsertRowid, username, email };
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      res.json({ error: err.message.includes('email') ? 'Email already registered' : 'Username already taken' });
    } else res.json({ error: 'Signup failed' });
  }
});

// ========== LOGIN ==========
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const loginField = cleanStr(username).toLowerCase();
  
  if (!loginField || !password) return res.json({ error: 'Enter username/email and password' });

  const user = mainDB.prepare('SELECT * FROM users WHERE username = ? OR email = ?')
    .get(loginField, loginField);
  
  if (!user) return res.json({ error: 'Account not found' });
  if (!bcrypt.compareSync(password, user.password)) return res.json({ error: 'Wrong password' });

  req.session.user = { id: user.id, username: user.username, email: user.email };
  res.json({ success: true, user: req.session.user });
});

// ========== LOGOUT ==========
app.get('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login.html?msg=Logged+out+successfully');
  });
});

// ========== 📊 DASHBOARD STATS ==========
app.get('/api/dashboard', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  
  const tx = mainDB.prepare(`SELECT * FROM transactions WHERE user_id = ?`).all(req.session.user.id);
  const buyers = mainDB.prepare(`SELECT COUNT(*) as count FROM buyers WHERE user_id = ?`).get(req.session.user.id).count;
  
  let totalSales = 0, totalCost = 0, totalFees = 0, profit = 0, soldCount = 0;
  tx.forEach(t => {
    if (t.sold_price > 0) {
      totalSales += t.sold_price || 0;
      totalCost += t.buy_price || 0;
      totalFees += t.fees || 0;
      profit += (t.sold_price || 0) - (t.buy_price || 0) - (t.shipping_cost || 0) - (t.fees || 0);
      soldCount++;
    }
  });

  const recent = mainDB.prepare(`SELECT t.*, b.name as buyer_name FROM transactions t LEFT JOIN buyers b ON t.buyer_id = b.id WHERE t.user_id = ? ORDER BY t.created_at DESC LIMIT 6`)
    .all(req.session.user.id);

  res.json({
    totalSales: Number(totalSales.toFixed(2)),
    totalCost: Number(totalCost.toFixed(2)),
    totalFees: Number(totalFees.toFixed(2)),
    totalProfit: Number(profit.toFixed(2)),
    soldCount,
    buyerCount: buyers,
    recentTransactions: recent
  });
});

// ========== 👤 PROFILE & SETTINGS ==========
app.get('/api/profile', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const user = mainDB.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?').get(req.session.user.id);
  const settings = mainDB.prepare('SELECT * FROM user_settings WHERE user_id = ?').get(req.session.user.id);
  res.json({ user, settings });
});

app.post('/api/change-password', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const { current, newPass } = req.body;
  if (!newPass || newPass.length < 6) return res.json({ error: 'New password needs at least 6 characters' });

  const user = mainDB.prepare('SELECT password FROM users WHERE id = ?').get(req.session.user.id);
  if (!bcrypt.compareSync(current, user.password)) return res.json({ error: 'Current password is wrong' });

  const newHash = bcrypt.hashSync(newPass, 10);
  mainDB.prepare('UPDATE users SET password = ? WHERE id = ?').run(newHash, req.session.user.id);
  res.json({ success: true, message: '✅ Password updated!' });
});

// ========== BUYER CRM ==========
app.get('/api/buyers/list', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const buyers = mainDB.prepare('SELECT * FROM buyers WHERE user_id = ? ORDER BY total_spent DESC, created_at DESC')
    .all(req.session.user.id);
  res.json({ buyers });
});

app.post('/api/buyers/add', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  let { name, contact, email, notes, status } = req.body;
  name = cleanStr(name);
  if (!name) return res.json({ error: 'Buyer name is required' });
  const result = mainDB.prepare(`INSERT INTO buyers (user_id, name, contact, email, notes, status) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(req.session.user.id, name, cleanStr(contact), cleanStr(email), cleanStr(notes), status || 'active');
  res.json({ success: true, buyerId: result.lastInsertRowid });
});

app.post('/api/buyers/delete', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  mainDB.prepare('DELETE FROM buyers WHERE id = ? AND user_id = ?').run(req.body.id, req.session.user.id);
  res.json({ success: true });
});

// ========== 💰 TRANSACTIONS — WITH IMAGES! ==========
app.get('/api/transactions/list', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const tx = mainDB.prepare(`SELECT t.*, b.name as buyer_name FROM transactions t LEFT JOIN buyers b ON t.buyer_id = b.id WHERE t.user_id = ? ORDER BY t.created_at DESC`)
    .all(req.session.user.id);
  tx.forEach(t => {
    t.profit = Number(((t.sold_price || 0) - (t.buy_price || 0) - (t.shipping_cost || 0) - (t.fees || 0)).toFixed(2));
  });
  res.json({ transactions: tx });
});

app.post('/api/transactions/add', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const { buyer_id, item_name, item_image, buy_price, sold_price, shipping_cost, fees, status, due_date, notes } = req.body;
  const result = mainDB.prepare(`INSERT INTO transactions 
    (user_id, buyer_id, item_name, item_image, buy_price, sold_price, shipping_cost, fees, status, due_date, notes) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(req.session.user.id, buyer_id || null, cleanStr(item_name), item_image || null, buy_price || 0, sold_price || 0, shipping_cost || 0, fees || 0, status || 'pending', due_date || null, cleanStr(notes) || '');
  res.json({ success: true, txId: result.lastInsertRowid });
});

app.post('/api/transactions/delete', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  mainDB.prepare('DELETE FROM transactions WHERE id = ? AND user_id = ?').run(req.body.id, req.session.user.id);
  res.json({ success: true });
});

// ========== 🔐 ADMIN PANEL ==========
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

console.log('🚀 RR Resell Tracker — ONLINE ✅');
app.listen(PORT);
