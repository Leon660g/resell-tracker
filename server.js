process.env.ADMIN_PASSWORD = "Giraffe";
process.env.SESSION_SECRET = "ResellTrackerSecret2026_HACKER_EDITION";

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

// ========== DATABASE — ALL RESOURCE TABLES ==========
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
    category TEXT DEFAULT 'General',
    purchase_price REAL DEFAULT 0,
    sold_price REAL DEFAULT 0,
    shipping_cost REAL DEFAULT 0,
    fees REAL DEFAULT 0,
    status TEXT DEFAULT 'Owned',
    purchase_date TEXT,
    sold_date TEXT,
    listed_price REAL DEFAULT 0,
    platform TEXT DEFAULT 'Vinted',
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(buyer_id) REFERENCES buyers(id) ON DELETE SET NULL
  );
  CREATE TABLE IF NOT EXISTS inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    item_name TEXT NOT NULL,
    item_image TEXT,
    category TEXT,
    purchase_price REAL DEFAULT 0,
    purchase_date TEXT,
    supplier TEXT,
    listed_price REAL DEFAULT 0,
    platform TEXT,
    status TEXT DEFAULT 'Available',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
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

// ========== MIDDLEWARE — HTTPS/LOGIN FIXED ==========
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: { secure: true, httpOnly: true, sameSite: 'none', maxAge: 100 * 24 * 60 * 60 * 1000 }
}));

function isValidEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function cleanStr(str) { return str ? str.trim().substring(0, 500) : ''; }

function requireAuth(req, res, next) {
  const safe = ['/login.html','/signup.html','/api/login','/api/signup','/api/me'];
  if (safe.some(p => req.path.startsWith(p))) return next();
  if (!req.session.user) return res.redirect('/login.html');
  next();
}
app.use(requireAuth);

// ========== 📷 IMAGE UPLOAD ==========
app.post('/api/upload-image', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Unauthorized' });
  const { base64, name } = req.body;
  if (!base64) return res.json({ error: 'No image data' });
  const ext = name?.endsWith('.png') ? '.png' : name?.endsWith('.gif') ? '.gif' : '.jpg';
  const filename = `${crypto.randomBytes(16).toString('hex')}${ext}`;
  const filepath = path.join(__dirname, 'public', 'uploads', filename);
  fs.writeFileSync(filepath, base64.replace(/^data:image\/\w+;base64,/, ''), 'base64');
  res.json({ success: true, url: `/uploads/${filename}` });
});

// ========== 🎨 AI IMAGE GENERATOR ==========
app.post('/api/generate-image', async (req, res) => {
  if (!req.session.user) return res.json({ error: 'Unauthorized' });
  const { prompt } = req.body;
  if (!prompt || prompt.length < 3) return res.json({ error: 'Description too short' });
  try {
    const q = encodeURIComponent(prompt + ', professional product photo, white background, clean studio lighting, high detail, 4k');
    res.json({ success: true, imageUrl: `https://image.pollinations.ai/prompt/${q}?width=512&height=512&nologo=true&seed=${Date.now()}` });
  } catch { res.json({ error: 'Generation failed' }); }
});

// ========== AUTH ==========
app.get('/api/me', (req, res) => res.json({ user: req.session.user || null }));

app.post('/api/signup', (req, res) => {
  let { username, email, password } = req.body;
  username = cleanStr(username).toLowerCase(); email = cleanStr(email).toLowerCase();
  if (!username || username.length < 2) return res.json({ error: 'Username too short' });
  if (!email || !isValidEmail(email)) return res.json({ error: 'Invalid email' });
  if (!password || password.length < 6) return res.json({ error: 'Min 6 chars' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const id = mainDB.prepare('INSERT INTO users (username,email,password) VALUES (?,?,?)').run(username,email,hash).lastInsertRowid;
    mainDB.prepare('INSERT INTO user_settings (user_id) VALUES (?)').run(id);
    req.session.user = { id, username, email };
    res.json({ success: true, user: req.session.user });
  } catch { res.json({ error: 'Username or email exists' }); }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const u = mainDB.prepare('SELECT * FROM users WHERE username=? OR email=?').get(cleanStr(username).toLowerCase(), cleanStr(username).toLowerCase());
  if (!u) return res.json({ error: 'Account not found' });
  if (!bcrypt.compareSync(password, u.password)) return res.json({ error: 'Wrong password' });
  req.session.user = { id: u.id, username: u.username, email: u.email };
  res.json({ success: true });
});

app.get('/api/logout', (req, res) => { req.session.destroy(() => { res.clearCookie('connect.sid'); res.redirect('/login.html'); }); });

// ========== 📊 DASHBOARD — FULL ANALYTICS ==========
app.get('/api/dashboard', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Login required' });
  const tx = mainDB.prepare('SELECT * FROM transactions WHERE user_id=?').all(req.session.user.id);
  const inv = mainDB.prepare('SELECT COUNT(*) c FROM inventory WHERE user_id=? AND status="Available"').get(req.session.user.id).c;
  const buyers = mainDB.prepare('SELECT COUNT(*) c FROM buyers WHERE user_id=?').get(req.session.user.id).c;
  
  let sales=0,cost=0,fees=0,profit=0,count=0;
  tx.forEach(t=>{
    if(t.sold_price>0){
      sales+=t.sold_price||0; cost+=t.purchase_price||0; fees+=t.fees||0;
      profit+=(t.sold_price||0)-(t.purchase_price||0)-(t.shipping_cost||0)-(t.fees||0);
      count++;
    }
  });
  const recent = mainDB.prepare('SELECT * FROM transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 5').all(req.session.user.id);
  res.json({
    totalSales: Number(sales.toFixed(2)), totalCost: Number(cost.toFixed(2)),
    totalFees: Number(fees.toFixed(2)), totalProfit: Number(profit.toFixed(2)),
    soldCount:count, inventoryCount:inv, buyerCount:buyers, recentTransactions:recent
  });
});

// ========== 💰 TRANSACTIONS API ==========
app.get('/api/transactions', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Login required' });
  const tx = mainDB.prepare('SELECT * FROM transactions WHERE user_id=? ORDER BY created_at DESC').all(req.session.user.id);
  tx.forEach(t=>{ t.profit = Number(((t.sold_price||0)-(t.purchase_price||0)-(t.shipping_cost||0)-(t.fees||0)).toFixed(2)); });
  res.json({ transactions:tx });
});

app.post('/api/transactions/add', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Login required' });
  const { item_name,item_image,category,purchase_price,sold_price,shipping_cost,fees,status,purchase_date,sold_date,platform,notes } = req.body;
  mainDB.prepare(`INSERT INTO transactions(user_id,item_name,item_image,category,purchase_price,sold_price,shipping_cost,fees,status,purchase_date,sold_date,platform,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(req.session.user.id,cleanStr(item_name),item_image,cleanStr(category),purchase_price||0,sold_price||0,shipping_cost||0,fees||0,status||'Owned',purchase_date,sold_date,cleanStr(platform),cleanStr(notes));
  res.json({ success:true });
});

app.post('/api/transactions/delete', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Login required' });
  mainDB.prepare('DELETE FROM transactions WHERE id=? AND user_id=?').run(req.body.id,req.session.user.id);
  res.json({ success:true });
});

// ========== 📦 INVENTORY API ==========
app.get('/api/inventory', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Login required' });
  res.json({ items:mainDB.prepare('SELECT * FROM inventory WHERE user_id=? ORDER BY created_at DESC').all(req.session.user.id) });
});

app.post('/api/inventory/add', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Login required' });
  const { item_name,item_image,category,purchase_price,purchase_date,supplier,listed_price,platform } = req.body;
  mainDB.prepare(`INSERT INTO inventory(user_id,item_name,item_image,category,purchase_price,purchase_date,supplier,listed_price,platform) VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(req.session.user.id,cleanStr(item_name),item_image,cleanStr(category),purchase_price||0,purchase_date,cleanStr(supplier),listed_price||0,cleanStr(platform));
  res.json({ success:true });
});

app.post('/api/inventory/mark-sold', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Login required' });
  const item = mainDB.prepare('SELECT * FROM inventory WHERE id=? AND user_id=?').get(req.body.id,req.session.user.id);
  if(!item) return res.json({error:'Not found'});
  mainDB.prepare(`INSERT INTO transactions(user_id,item_name,item_image,category,purchase_price,status,purchase_date,platform) VALUES (?,?,?,?,?,?,?,?)`)
    .run(req.session.user.id,item.item_name,item.item_image,item.category,item.purchase_price,'Sold',item.purchase_date,item.platform);
  mainDB.prepare('DELETE FROM inventory WHERE id=? AND user_id=?').run(req.body.id,req.session.user.id);
  res.json({ success:true });
});

// ========== 👥 BUYERS API ==========
app.get('/api/buyers', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Login required' });
  res.json({ buyers:mainDB.prepare('SELECT * FROM buyers WHERE user_id=? ORDER BY total_spent DESC').all(req.session.user.id) });
});

app.post('/api/buyers/add', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Login required' });
  const {name,contact,email,notes}=req.body;
  mainDB.prepare('INSERT INTO buyers(user_id,name,contact,email,notes) VALUES (?,?,?,?,?)').run(req.session.user.id,cleanStr(name),cleanStr(contact),cleanStr(email),cleanStr(notes));
  res.json({ success:true });
});

console.log('🟢 ResellTracker SYSTEM ONLINE — ACCESS GRANTED ✅');
app.listen(PORT);
