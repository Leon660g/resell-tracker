process.env.ADMIN_PASSWORD = "Giraffe";
process.env.SESSION_SECRET = "ResellTrackerSecret2026";

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
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
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS user_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    data_type TEXT NOT NULL,
    data_json TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
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
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
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

// ✅ PERMANENT LOGIN — 100 DAYS = REMEMBERS FOREVER
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 100 * 24 * 60 * 60 * 1000 // ✅ 100 DAYS — PERMANENT REMEMBER
  }
}));

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ✅ PUBLIC ROUTES — ADMIN WORKS WITHOUT LOGIN
function requireAuth(req, res, next) {
  const publicPaths = [
    '/login.html',
    '/api/login',
    '/api/signup',
    '/api/me',
    '/api/admin/login',
    '/api/admin/alldata',
    '/api/admin/notifications/read'
  ];
  if (publicPaths.some(p => req.path.startsWith(p))) {
    return next();
  }
  if (!req.session.user) return res.redirect('/login.html');
  next();
}
app.use(requireAuth);

// ========== CHECK LOGIN STATUS ==========
app.get('/api/me', (req, res) => {
  res.json({
    user: req.session.user || null,
    isAdmin: !!req.session.isAdmin
  });
});

// ========== SIGNUP — SAVE TO DATABASE ==========
app.post('/api/signup', (req, res) => {
  const { username, email, password } = req.body;
  
  if (!username || username.length < 2) return res.json({ error: 'Username needs at least 2 characters' });
  if (!email || !isValidEmail(email)) return res.json({ error: 'Enter a valid email address' });
  if (!password || password.length < 6) return res.json({ error: 'Password needs at least 6 characters' });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const stmt = mainDB.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
    const result = stmt.run(username.toLowerCase().trim(), email.toLowerCase().trim(), hash);
    
    adminDB.prepare('INSERT INTO notifications (type, message) VALUES (?, ?)').run(
      'signup',
      `🆕 New user: ${username} — ${email}`
    );

    // ✅ AUTO-LOGIN AFTER SIGNUP
    req.session.user = { id: result.lastInsertRowid, username, email };
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      res.json({ error: err.message.includes('email') ? 'Email already registered' : 'Username already taken' });
    } else res.json({ error: 'Signup failed' });
  }
});

// ========== LOGIN — REMEMBERS FOREVER ==========
app.post('/api/login', (req, res) => {
  const { username, email, password } = req.body;
  const loginField = username || email;
  
  if (!loginField || !password) {
    return res.json({ error: 'Enter username/email and password' });
  }

  const user = mainDB.prepare('SELECT * FROM users WHERE username = ? OR email = ?')
    .get(loginField.toLowerCase().trim(), loginField.toLowerCase().trim());
  
  if (!user) return res.json({ error: 'Account not found' });
  if (!bcrypt.compareSync(password, user.password)) {
    return res.json({ error: 'Wrong password' });
  }

  // ✅ SET SESSION — REMEMBERS 100 DAYS
  req.session.user = { id: user.id, username: user.username, email: user.email };
  res.json({ success: true, user: req.session.user });
});

// ========== LOGOUT ==========
app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// ========== SAVE/LOAD USER DATA ==========
app.post('/api/user/save', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const { dataType, data } = req.body;
  mainDB.prepare(`INSERT OR REPLACE INTO user_data (user_id, data_type, data_json, updated_at) VALUES (?, ?, ?, datetime('now'))`)
    .run(req.session.user.id, dataType, JSON.stringify(data));
  res.json({ success: true });
});

app.get('/api/user/load/:dataType', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const row = mainDB.prepare('SELECT data_json FROM user_data WHERE user_id = ? AND data_type = ?')
    .get(req.session.user.id, req.params.dataType);
  res.json({ data: row ? JSON.parse(row.data_json) : null });
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

// ========== TRANSACTIONS ==========
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

// ========== ADMIN PANEL API ==========
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

console.log('🚀 RR Resell Tracker — FULL SYSTEM ONLINE');
// ========== 🔐 ENCRYPTION — SECURELY STORE VINTED TOKENS ==========
const crypto = require('crypto');
const ENCRYPTION_KEY = crypto.scryptSync(process.env.SESSION_SECRET, 'salt', 32); // Derive from your secret
const IV_LENGTH = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
  try {
    const parts = text.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch { return null; }
}

// ========== VINTED TOKEN DATABASE SETUP ==========
mainDB.exec(`
  CREATE TABLE IF NOT EXISTS vinted_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    refresh_token TEXT NOT NULL,
    access_token TEXT,
    token_expires_at TEXT,
    last_sync_at TEXT,
    sync_status TEXT DEFAULT 'idle',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ========== SAVE VINTED TOKEN — ENCRYPTED ==========
app.post('/api/vinted/save-token', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const { refreshToken } = req.body;
  if (!refreshToken || refreshToken.length < 20) {
    return res.json({ error: 'Please enter a valid Refresh Token' });
  }

  const encrypted = encrypt(refreshToken.trim());
  
  mainDB.prepare(`INSERT OR REPLACE INTO vinted_credentials 
    (user_id, refresh_token, access_token, token_expires_at, last_sync_at, sync_status) 
    VALUES (?, ?, NULL, NULL, NULL, 'pending')`)
    .run(req.session.user.id, encrypted);

  res.json({ success: true, message: '✅ Vinted token saved! Sync will start shortly...' });
});

// ========== DELETE VINTED TOKEN ==========
app.post('/api/vinted/remove-token', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  mainDB.prepare('DELETE FROM vinted_credentials WHERE user_id = ?').run(req.session.user.id);
  res.json({ success: true, message: '✅ Vinted sync removed' });
});

// ========== GET VINTED SYNC STATUS ==========
app.get('/api/vinted/status', (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  const row = mainDB.prepare('SELECT id, last_sync_at, sync_status FROM vinted_credentials WHERE user_id = ?')
    .get(req.session.user.id);
  res.json({ 
    hasToken: !!row, 
    lastSync: row?.last_sync_at,
    status: row?.sync_status || 'idle'
  });
});

// ========== 🔄 MANUAL SYNC TRIGGER (also runs auto every 4h) ==========
app.post('/api/vinted/sync-now', async (req, res) => {
  if (!req.session.user) return res.json({ error: 'Not logged in' });
  
  const creds = mainDB.prepare('SELECT * FROM vinted_credentials WHERE user_id = ?').get(req.session.user.id);
  if (!creds) return res.json({ error: 'No Vinted token found' });

  const refreshToken = decrypt(creds.refresh_token);
  if (!refreshToken) return res.json({ error: 'Token corrupted — please re-enter' });

  try {
    // Step 1: Get fresh Access Token from Vinted
    const tokenRes = await fetch('https://www.vinted.fr/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: 'read'
      })
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      mainDB.prepare('UPDATE vinted_credentials SET sync_status = "error" WHERE user_id = ?').run(req.session.user.id);
      return res.json({ error: '❌ Invalid or expired Refresh Token — please update it' });
    }

    const accessToken = tokenData.access_token;
    const expiresAt = new Date(Date.now() + (tokenData.expires_in || 86400) * 1000).toISOString();

    // Step 2: Fetch User's Sales / Transactions
    const salesRes = await fetch('https://api.vinted.com/me/transactions?type=sold&per_page=50', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    const salesData = await salesRes.json();
    const items = salesData.transactions || [];
    let newSalesCount = 0;

    // Step 3: Auto-Add NEW sales to database
    for (const item of items) {
      const existing = mainDB.prepare('SELECT id FROM transactions WHERE user_id = ? AND item_name LIKE ? AND sold_price = ?')
        .get(req.session.user.id, `%${item.title || item.item_name}%`, (item.total_amount || 0) / 100);

      if (!existing && item.title && item.total_amount > 0) {
        const soldPrice = Number((item.total_amount / 100).toFixed(2));
        const fee = Number(((item.fee_amount || 0) / 100).toFixed(2));
        
        mainDB.prepare(`INSERT INTO transactions 
          (user_id, item_name, buy_price, sold_price, shipping_cost, fees, status, notes) 
          VALUES (?, ?, 0, ?, 0, ?, 'sold', '🔄 Auto-imported from Vinted')`)
          .run(req.session.user.id, item.title || 'Vinted Item', soldPrice, fee);
        newSalesCount++;
      }
    }

    // Step 4: Update sync status
    mainDB.prepare(`UPDATE vinted_credentials 
      SET access_token = ?, token_expires_at = ?, last_sync_at = datetime('now'), sync_status = 'ok' 
      WHERE user_id = ?`)
      .run(accessToken, expiresAt, req.session.user.id);

    res.json({ 
      success: true, 
      message: newSalesCount > 0 
        ? `✅ Synced! ${newSalesCount} NEW sale(s) added!` 
        : '✅ Synced! No new sales found.',
      newSalesCount
    });

  } catch (err) {
    console.error('Vinted Sync Error:', err);
    mainDB.prepare('UPDATE vinted_credentials SET sync_status = "error" WHERE user_id = ?').run(req.session.user.id);
    res.json({ error: '❌ Sync failed — check Refresh Token' });
  }
});

// ========== ⏰ AUTO-SYNC BACKGROUND JOB (Every 4 Hours) ==========
setInterval(async () => {
  try {
    const allCreds = mainDB.prepare('SELECT * FROM vinted_credentials').all();
    console.log(`🔄 Auto-Sync: Checking ${allCreds.length} Vinted accounts...`);

    for (const cred of allCreds) {
      try {
        const refreshToken = decrypt(cred.refresh_token);
        if (!refreshToken) continue;

        // Get fresh access token
        const tokenRes = await fetch('https://www.vinted.fr/oauth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ grant_type: 'refresh_token', refresh_token: refreshToken, scope: 'read' })
        });
        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) continue;

        // Fetch sales
        const salesRes = await fetch('https://api.vinted.com/me/transactions?type=sold&per_page=50', {
          headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
        });
        const salesData = await salesRes.json();
        const items = salesData.transactions || [];

        // Import NEW sales
        for (const item of items) {
          const existing = mainDB.prepare('SELECT id FROM transactions WHERE user_id = ? AND item_name LIKE ? AND sold_price = ?')
            .get(cred.user_id, `%${item.title || item.item_name}%`, (item.total_amount || 0) / 100);
          
          if (!existing && item.title && item.total_amount > 0) {
            const soldPrice = Number((item.total_amount / 100).toFixed(2));
            const fee = Number(((item.fee_amount || 0) / 100).toFixed(2));
            mainDB.prepare(`INSERT INTO transactions 
              (user_id, item_name, buy_price, sold_price, shipping_cost, fees, status, notes) 
              VALUES (?, ?, 0, ?, 0, ?, 'sold', '🔄 Auto-imported from Vinted')`)
              .run(cred.user_id, item.title, soldPrice, fee);
          }
        }

        mainDB.prepare(`UPDATE vinted_credentials SET last_sync_at = datetime('now'), sync_status = 'ok' WHERE id = ?`)
          .run(cred.id);
      } catch (e) { /* Skip individual errors */ }
    }
    console.log('✅ Auto-Sync cycle complete');
  } catch (e) { console.error('Auto-Sync Error:', e); }
}, 4 * 60 * 60 * 1000); // ⏰ EVERY 4 HOURS
app.listen(PORT);
