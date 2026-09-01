require('dotenv').config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const Database = require("better-sqlite3");
const { customAlphabet } = require("nanoid");
const morgan = require("morgan");

const PORT = process.env.PORT || 3456;
const CAPACITY = parseInt(process.env.CAPACITY || "15000", 10);
const ADMIN_KEY = process.env.ADMIN_KEY || "changeme";
const DB_PATH = process.env.DB_PATH || "./data/app.db";

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login_id TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    usdt_address TEXT NOT NULL,
    token_address TEXT NOT NULL,
    referral_code TEXT UNIQUE NOT NULL,
    referred_by TEXT,
    status TEXT DEFAULT 'pending',
    admin_notes TEXT,
    quiz_answers TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_users_referral ON users(referral_code);
`);

const stmts = {
  count: db.prepare("SELECT COUNT(*) AS c FROM users"),
  emailExists: db.prepare("SELECT 1 FROM users WHERE email = ?"),
  codeExists: db.prepare("SELECT 1 FROM users WHERE referral_code = ?"),
  loginIdExists: db.prepare("SELECT 1 FROM users WHERE login_id = ?"),
  referralValid: db.prepare("SELECT 1 FROM users WHERE referral_code = ?"),
  getById: db.prepare("SELECT * FROM users WHERE id = ?"),
  getByLoginId: db.prepare("SELECT login_id, referral_code, status, admin_notes FROM users WHERE login_id = ?"),
  insert: db.prepare(`INSERT INTO users (login_id, email, usdt_address, token_address, referral_code, referred_by, quiz_answers, created_at) VALUES (@login_id, @email, @usdt_address, @token_address, @referral_code, @referred_by, @quiz_answers, @created_at)`),
  updateStatus: db.prepare("UPDATE users SET status = @status, admin_notes = @admin_notes WHERE id = @id"),
  getPending: db.prepare("SELECT * FROM users WHERE status = ? ORDER BY id DESC LIMIT 100")
};

const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const genCode = customAlphabet(codeAlphabet, 8);
const genLogin = customAlphabet(codeAlphabet, 6);

function uniqueReferralCode() { let c; do { c = "DJ-" + genCode(); } while (stmts.codeExists.get(c)); return c; }
function uniqueLoginId() { let i; do { i = "USR-" + genLogin(); } while (stmts.loginIdExists.get(i)); return i; }

const MAINSTREAM_EMAILS = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'protonmail.com', 'aol.com', 'mail.com', 'zoho.com', 'yandex.com', 'live.com', 'msn.com'];
function isValidEmail(e) { if (!e) return false; const p = e.trim().split('@'); return p.length === 2 && MAINSTREAM_EMAILS.includes(p[1].toLowerCase()); }
function isValidUsdt(a) { return /^0x[a-fA-F0-9]{40}$/.test(a) || /^T[a-zA-Z0-9]{33}$/.test(a); }
function isValidPoly(a) { return /^0x[a-fA-F0-9]{40}$/.test(a); }

const signupTx = db.transaction((d) => {
  const cur = stmts.count.get().c;
  if (cur >= CAPACITY) throw new Error("FULL");
  if (stmts.emailExists.get(d.email)) throw new Error("EXISTS");
  let refBy = null;
  if (d.refCode) { const n = d.refCode.trim().toUpperCase(); if (stmts.referralValid.get(n)) refBy = n; }
  const login_id = uniqueLoginId();
  const referral_code = uniqueReferralCode();
  stmts.insert.run({ login_id, email: d.email, usdt_address: d.usdt, token_address: d.poly, referral_code, referred_by: refBy, quiz_answers: JSON.stringify(d.quiz || {}), created_at: new Date().toISOString() });
  return { login_id, referral_code, referred_by: refBy, spotsLeft: CAPACITY - (cur + 1) };
});

const app = express();

// Set MIME types for mobile compatibility
express.static.mime.define({
  'video/mp4': ['mp4', 'm4v'],
  'video/webm': ['webm'],
  'image/webp': ['webp']
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "blob:"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
    },
  },
  hsts: false 
}));

app.use(compression());
app.use(cors()); 
app.use(express.json({ limit: "100kb" }));

app.use(express.static(path.join(__dirname, "public"), {
  maxAge: '30d',
  etag: true
}));

app.use(morgan('combined'));

app.use((req, res, next) => {
  if (req.path.startsWith('/api/admin') && req.headers['x-admin-key'] !== ADMIN_KEY) {
    console.warn(`[SECURITY] Failed admin access attempt from IP: ${req.ip} at ${new Date().toISOString()}`);
  }
  next();
});

app.get("/api/status", (req, res) => { const c = stmts.count.get().c; res.json({ capacity: CAPACITY, signedUp: c, spotsLeft: CAPACITY - c, isOpen: c < CAPACITY }); });
app.get("/api/user/:loginId", (req, res) => { const user = stmts.getByLoginId.get(req.params.loginId); if (!user) return res.status(404).json({ error: "Not found" }); res.json({ loginId: user.login_id, referralCode: user.referral_code, status: user.status, notes: user.admin_notes }); });

app.post("/api/signup", (req, res) => {
  try {
    const { email, usdtAddress, tokenAddress, referralCode, quizAnswers } = req.body;
    if (typeof quizAnswers !== 'object' || quizAnswers === null) return res.status(400).json({ error: "Invalid quiz data format." });
    if (JSON.stringify(quizAnswers).length > 2000) return res.status(400).json({ error: "Quiz data payload is too large." });
    if (!isValidEmail(email)) return res.status(400).json({ error: "Please enter a valid email address." });
    if (!isValidUsdt(usdtAddress)) return res.status(400).json({ error: "Invalid USDT wallet address." });
    if (!isValidPoly(tokenAddress)) return res.status(400).json({ error: "Invalid Polygon wallet address." });
    const result = signupTx({ email: email.trim().toLowerCase(), usdt: usdtAddress.trim(), poly: tokenAddress.trim(), refCode: referralCode, quiz: quizAnswers });
    res.status(201).json({ success: true, message: "Signup successful!", loginId: result.login_id, referralCode: result.referral_code, referredBy: result.referred_by, spotsLeft: result.spotsLeft });
  } catch (e) {
    if (e.message === "FULL") return res.status(403).json({ error: "Signups are full." });
    if (e.message === "EXISTS") return res.status(409).json({ error: "Email already used." });
    console.error(e);
    res.status(500).json({ error: "Something went wrong." });
  }
});

app.get("/api/admin/claims", (req, res) => { if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" }); res.json(stmts.getPending.all(req.query.status || 'pending', 100).map(r => ({ ...r, quiz_answers: r.quiz_answers ? JSON.parse(r.quiz_answers) : null }))); });
app.post("/api/admin/claims/:id/status", (req, res) => { if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" }); stmts.updateStatus.run({ id: req.params.id, status: req.body.status, admin_notes: req.body.admin_notes || '' }); res.json({ ok: true }); });
app.get("/api/admin/stats", (req, res) => { if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" }); const t = stmts.count.get().c; res.json({ total: t, pending: db.prepare("SELECT COUNT(*) c FROM users WHERE status='pending'").get().c }); });
app.get("/api/admin/export", (req, res) => { if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" }); res.send("CSV Data"); });

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ SERVER RUNNING\n Local: http://localhost:${PORT}\n Network: http://192.168.0.100:${PORT}\n MIME types configured for mobile.\n`);
});
