const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const initSqlJs = require("sql.js");
const path = require("path");
const bodyParser = require("body-parser");

const app = express();
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());
app.use("/uploads", express.static("uploads"));

let db;

(async () => {
  const SQL = await initSqlJs();
  if (fs.existsSync("mhyasi.db")) {
    const fileBuffer = fs.readFileSync("mhyasi.db");
    db = new SQL.Database(fileBuffer);
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
        unlock_until INTEGER
      );
      CREATE TABLE products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        price REAL,
        qty INTEGER
      );
      CREATE TABLE invoices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        invoice_id TEXT,
        items TEXT,
        total REAL,
        created_at INTEGER
      );
      CREATE TABLE requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount REAL,
        details TEXT
      );
      CREATE TABLE codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        for_user INTEGER,
        code TEXT,
        until INTEGER
      );
    `);
    saveDb();
  }
})();

function saveDb() {
  const data = db.export();
  fs.writeFileSync("mhyasi.db", Buffer.from(data));
}

const SECRET = "mhyasi-secret";

// helpers
function auth(req, res, next) {
  const h = req.headers["authorization"];
  if (!h) return res.status(401).json({ ok: false, error: "No token" });
  try {
    const token = h.split(" ")[1];
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: "Invalid token" });
  }
}

// register
app.post("/api/register", (req, res) => {
  const { username, password, shop_name, shop_address } = req.body;
  if (!username || !password) return res.json({ ok: false, error: "missing fields" });
  const hash = bcrypt.hashSync(password, 8);
  try {
    db.run(
      "INSERT INTO users (username, password, shop_name, shop_address) VALUES (?,?,?,?)",
      [username, hash, shop_name || "", shop_address || ""]
    );
    saveDb();
    res.json({ ok: true });
  } catch {
    res.json({ ok: false, error: "username exists" });
  }
});

// login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const r = db.exec("SELECT * FROM users WHERE username=?", [username]);
  if (!r[0]) return res.json({ ok: false, error: "User not found" });
  const u = r[0].values[0];
  if (!bcrypt.compareSync(password, u[2])) return res.json({ ok: false, error: "Wrong pass" });
  const token = jwt.sign({ id: u[0], username: u[1], role: u[3] }, SECRET);
  res.json({
    ok: true,
    token,
    user: {
      id: u[0],
      username: u[1],
      role: u[3],
      shop_name: u[4],
      shop_address: u[5],
      logo_path: u[6],
    },
  });
});

// me
app.get("/api/me", auth, (req, res) => {
  const r = db.exec("SELECT * FROM users WHERE id=?", [req.user.id]);
  if (!r[0]) return res.json({ ok: false });
  const u = r[0].values[0];
  res.json({
    ok: true,
    user: {
      id: u[0],
      username: u[1],
      role: u[3],
      shop_name: u[4],
      shop_address: u[5],
      logo_path: u[6],
    },
  });
});

// profile update
app.post("/api/profile", auth, (req, res) => {
  const { shop_name, shop_address } = req.body;
  db.run("UPDATE users SET shop_name=?, shop_address=? WHERE id=?", [
    shop_name,
    shop_address,
    req.user.id,
  ]);
  saveDb();
  res.json({ ok: true });
});

// upload logo
const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});
const upload = multer({ storage });

app.post("/api/profile/logo", auth, upload.single("logo"), (req, res) => {
  const pathUrl = "/uploads/" + req.file.filename;
  db.run("UPDATE users SET logo_path=? WHERE id=?", [pathUrl, req.user.id]);
  saveDb();
  res.json({ ok: true, logo_path: pathUrl });
});

// products
app.get("/api/products", auth, (req, res) => {
  const r = db.exec("SELECT * FROM products WHERE user_id=?", [req.user.id]);
  const arr = r[0]
    ? r[0].values.map((v) => ({ id: v[0], name: v[2], price: v[3], qty: v[4] }))
    : [];
  res.json({ ok: true, products: arr });
});

app.post("/api/products", auth, (req, res) => {
  const { name, price, qty } = req.body;
  db.run("INSERT INTO products (user_id,name,price,qty) VALUES (?,?,?,?)", [
    req.user.id,
    name,
    price,
    qty,
  ]);
  saveDb();
  res.json({ ok: true });
});

app.put("/api/products/:id", auth, (req, res) => {
  const { name, price, qty } = req.body;
  db.run("UPDATE products SET name=?,price=?,qty=? WHERE id=? AND user_id=?", [
    name,
    price,
    qty,
    req.params.id,
    req.user.id,
  ]);
  saveDb();
  res.json({ ok: true });
});

app.delete("/api/products/:id", auth, (req, res) => {
  db.run("DELETE FROM products WHERE id=? AND user_id=?", [req.params.id, req.user.id]);
  saveDb();
  res.json({ ok: true });
});

// invoices (auto reduce stock)
app.post("/api/invoices", auth, (req, res) => {
  const { invoice_id, items, total } = req.body;
  const now = Math.floor(Date.now() / 1000);
  db.run("INSERT INTO invoices (user_id,invoice_id,items,total,created_at) VALUES (?,?,?,?,?)", [
    req.user.id,
    invoice_id,
    JSON.stringify(items),
    total,
    now,
  ]);
  items.forEach((it) => {
    db.run("UPDATE products SET qty = qty - ? WHERE id=? AND user_id=?", [
      it.qty,
      it.id,
      req.user.id,
    ]);
  });
  saveDb();
  res.json({ ok: true });
});

app.get("/api/invoices", auth, (req, res) => {
  const r = db.exec("SELECT * FROM invoices WHERE user_id=?", [req.user.id]);
  const arr = r[0]
    ? r[0].values.map((v) => ({
        invoice_id: v[2],
        items: v[3],
        total: v[4],
        created_at: v[5],
      }))
    : [];
  res.json({ ok: true, invoices: arr });
});

app.get("/", (req, res) => {
  res.json({ ok: true, msg: "Mhyasi Store API" });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`✅ Mhyasi Store running on port ${PORT}`));
