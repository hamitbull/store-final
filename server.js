// server.js — Mhyasi Store (sql.js version)
// Run: npm install && node server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const initSqlJs = require('sql.js');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'mhyasi_secret_key';
const DB_FILE = path.join(__dirname, 'data.sqlite');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

let db, SQL;

function saveDb() {
  const data = db.export();
  fs.writeFileSync(DB_FILE, Buffer.from(data));
}
function run(sql, params = []) {
  db.run(sql, params);
  saveDb();
}
function all(sql, params = []) {
  const stmt = db.prepare(sql, params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}
function get(sql, params = []) {
  const stmt = db.prepare(sql, params);
  const row = stmt.step() ? stmt.getAsObject() : null;
  stmt.free();
  return row;
}
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

(async () => {
  SQL = await initSqlJs();
  if (fs.existsSync(DB_FILE)) {
    const file = fs.readFileSync(DB_FILE);
    db = new SQL.Database(file);
    console.log('✅ Loaded existing data.sqlite');
  } else {
    db = new SQL.Database();
    db.run(`
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user',
        shop_name TEXT,
        shop_address TEXT,
        logo_path TEXT,
        unlocked_until INTEGER
      );
      CREATE TABLE products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        price REAL,
        qty INTEGER,
        created_at INTEGER
      );
      CREATE TABLE invoices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        invoice_id TEXT,
        customer TEXT,
        items TEXT,
        total REAL,
        created_at INTEGER
      );
      CREATE TABLE requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount INTEGER,
        details TEXT,
        status TEXT DEFAULT 'pending',
        created_at INTEGER
      );
      CREATE TABLE unlock_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE,
        for_username TEXT,
        when_created INTEGER,
        until INTEGER,
        used INTEGER DEFAULT 0,
        used_by TEXT,
        used_at INTEGER
      );
    `);
    const pass = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT INTO users (username,password,role,shop_name) VALUES (?,?,?,?)`, ['admin', pass, 'admin', 'Mhyasi Admin']);
    saveDb();
    console.log("✅ Database created with default admin: admin / admin123");
  }

  const app = express();
  app.use(cors());
  app.use(bodyParser.json({ limit: '2mb' }));
  app.use('/uploads', express.static(UPLOAD_DIR));

  // Health
  app.get('/', (req, res) => res.json({ ok: true, msg: 'Mhyasi Store API' }));

  // Register
  app.post('/api/register', (req, res) => {
    try {
      const { username, password, shop_name, shop_address } = req.body;
      if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
      const exists = get(`SELECT id FROM users WHERE username=?`, [username]);
      if (exists) return res.status(400).json({ error: 'User exists' });
      const hash = bcrypt.hashSync(password, 10);
      run(`INSERT INTO users (username,password,shop_name,shop_address) VALUES (?,?,?,?)`, [username, hash, shop_name || '', shop_address || '']);
      return res.json({ ok: true });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: 'server error' });
    }
  });

  // Login
  app.post('/api/login', (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
      const user = get(`SELECT * FROM users WHERE username=?`, [username]);
      if (!user) return res.status(400).json({ error: 'Invalid credentials' });
      if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Invalid credentials' });
      const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
      return res.json({ ok: true, token, user: { id: user.id, username: user.username, role: user.role, shop_name: user.shop_name, shop_address: user.shop_address, logo_path: user.logo_path, unlocked_until: user.unlocked_until } });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: 'server error' });
    }
  });

  // Me
  app.get('/api/me', auth, (req, res) => {
    const u = get(`SELECT id,username,role,shop_name,shop_address,logo_path,unlocked_until FROM users WHERE id=?`, [req.user.id]);
    if (!u) return res.status(404).json({ error: 'Not found' });
    return res.json({ ok: true, user: u });
  });

  // Upload logo
  app.post('/api/profile/logo', auth, upload.single('logo'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const logo_path = `/uploads/${req.file.filename}`;
    run(`UPDATE users SET logo_path=? WHERE id=?`, [logo_path, req.user.id]);
    return res.json({ ok: true, logo_path });
  });

  // Update profile
  app.post('/api/profile', auth, (req, res) => {
    const { shop_name, shop_address } = req.body;
    run(`UPDATE users SET shop_name=?, shop_address=? WHERE id=?`, [shop_name, shop_address, req.user.id]);
    return res.json({ ok: true });
  });

  // Products
  app.post('/api/products', auth, (req, res) => {
    const { name, price, qty } = req.body;
    if (!name) return res.status(400).json({ error: 'Missing name' });
    run(`INSERT INTO products (user_id,name,price,qty,created_at) VALUES (?,?,?,?,?)`, [req.user.id, name, price || 0, qty || 0, Math.floor(Date.now()/1000)]);
    return res.json({ ok: true });
  });

  app.get('/api/products', auth, (req, res) => {
    const rows = all(`SELECT * FROM products WHERE user_id=? ORDER BY id DESC`, [req.user.id]);
    return res.json({ ok: true, products: rows });
  });

  app.put('/api/products/:id', auth, (req, res) => {
    const id = req.params.id;
    const { name, price, qty } = req.body;
    run(`UPDATE products SET name=?, price=?, qty=? WHERE id=? AND user_id=?`, [name, price || 0, qty || 0, id, req.user.id]);
    return res.json({ ok: true });
  });

  app.delete('/api/products/:id', auth, (req, res) => {
    const id = req.params.id;
    run(`DELETE FROM products WHERE id=? AND user_id=?`, [id, req.user.id]);
    return res.json({ ok: true });
  });

  // Create invoice (complete sale) - server checks unlocked_until
  app.post('/api/invoices', auth, (req, res) => {
    const { invoice_id, customer, items, total } = req.body;
    const user = get(`SELECT unlocked_until, username FROM users WHERE id=?`, [req.user.id]);
    const nowMs = Date.now();
    if (!user.unlocked_until || Number(user.unlocked_until) < nowMs) {
      return res.status(403).json({ error: 'account locked. Request unlock' });
    }
    run(`INSERT INTO invoices (user_id,invoice_id,customer,items,total,created_at) VALUES (?,?,?,?,?,?)`, [req.user.id, invoice_id, customer || '', JSON.stringify(items || []), total || 0, Math.floor(nowMs/1000)]);
    return res.json({ ok: true });
  });

  app.get('/api/invoices', auth, (req, res) => {
    const rows = all(`SELECT * FROM invoices WHERE user_id=? ORDER BY id DESC`, [req.user.id]);
    rows.forEach(r => r.items = JSON.parse(r.items || '[]'));
    return res.json({ ok: true, invoices: rows });
  });

  // Requests (user asks admin to approve)
  app.post('/api/request', auth, (req, res) => {
    const { amount, details } = req.body;
    run(`INSERT INTO requests (user_id,amount,details,created_at) VALUES (?,?,?,?)`, [req.user.id, amount || 0, details || '', Math.floor(Date.now()/1000)]);
    return res.json({ ok: true });
  });

  // Admin: list requests
  app.get('/api/requests', auth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const rows = all(`SELECT r.*, u.username FROM requests r JOIN users u ON r.user_id = u.id ORDER BY r.created_at DESC`);
    return res.json({ ok: true, requests: rows });
  });

  // Admin: approve (duration & unit)
  app.post('/api/approve', auth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const { requestId, duration, unit } = req.body;
    const r = get(`SELECT r.*, u.username FROM requests r JOIN users u ON u.id = r.user_id WHERE r.id=?`, [requestId]);
    if (!r) return res.status(404).json({ error: 'Request not found' });
    const now = Math.floor(Date.now()/1000);
    let until = now + (Number(duration) || 30) * 24 * 60 * 60;
    if (unit === 'months') until = now + (Number(duration) || 1) * 30 * 24 * 60 * 60;
    if (unit === 'years') until = now + (Number(duration) || 1) * 365 * 24 * 60 * 60;
    const code = "UNLK-" + Math.random().toString(36).substr(2,8).toUpperCase();
    run(`INSERT INTO unlock_codes (code,for_username,when_created,until) VALUES (?,?,?,?)`, [code, r.username, now, until * 1000]);
    run(`UPDATE requests SET status='approved' WHERE id=?`, [requestId]);
    return res.json({ ok: true, code, for: r.username, until: until * 1000 });
  });

  // Admin: decline
  app.post('/api/decline', auth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const { requestId } = req.body;
    run(`UPDATE requests SET status='declined' WHERE id=?`, [requestId]);
    return res.json({ ok: true });
  });

  // Admin: list codes
  app.get('/api/codes', auth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const rows = all(`SELECT * FROM unlock_codes ORDER BY id DESC`);
    return res.json({ ok: true, codes: rows });
  });

  // Redeem code (user)
  app.post('/api/redeem', auth, (req, res) => {
    const { code } = req.body;
    const c = get(`SELECT * FROM unlock_codes WHERE code=?`, [code]);
    if (!c) return res.status(404).json({ error: 'Invalid code' });
    if (c.used) return res.status(400).json({ error: 'Code already used' });
    const now = Math.floor(Date.now()/1000);
    if (Number(c.until) < now * 1000) return res.status(400).json({ error: 'Code expired' });
    run(`UPDATE unlock_codes SET used=1, used_by=?, used_at=? WHERE id=?`, [req.user.username, now, c.id]);
    run(`UPDATE users SET unlocked_until=? WHERE username=?`, [c.until, req.user.username]);
    return res.json({ ok: true, msg: 'Account unlocked' });
  });

  // Optional: admin verify pay (not implemented here; placeholder)
  app.post('/api/verify-paystack', auth, (req, res) => {
    return res.json({ ok: false, error: 'Not configured' });
  });

  app.listen(PORT, () => console.log(`✅ Mhyasi Store running on port ${PORT}`));
})();
