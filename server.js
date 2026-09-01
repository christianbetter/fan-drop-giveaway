require("dotenv").config();
const path = require("path");
const fs = require("fs");
const https = require("https"); // Added for HTTPS
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit"); // Added
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

// Updated schema to include fan_profile and deposit_address_used for better admin tracking
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
    fan_profile TEXT,
    deposit_address_used TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_users_referral ON users(referral_code);
  CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
`);

const stmts = {
  count: db.prepare("SELECT COUNT(*) AS c FROM users"),
  emailExists: db.prepare("SELECT 1 FROM users WHERE email = ?"),
  codeExists: db.prepare("SELECT 1 FROM users WHERE referral_code = ?"),
  loginIdExists: db.prepare("SELECT 1 FROM users WHERE login_id = ?"),
  referralValid: db.prepare("SELECT 1 FROM users WHERE referral_code = ?"),
  getByLoginId: db.prepare(
    "SELECT login_id, referral_code, status, admin_notes FROM users WHERE login_id = ?",
  ),
  insert: db.prepare(`
    INSERT INTO users (login_id, email, usdt_address, token_address, referral_code, referred_by, quiz_answers, fan_profile, deposit_address_used, created_at) 
    VALUES (@login_id, @email, @usdt_address, @token_address, @referral_code, @referred_by, @quiz_answers, @fan_profile, @deposit_address_used, @created_at)
  `),
  updateStatus: db.prepare(
    "UPDATE users SET status = @status, admin_notes = @admin_notes WHERE id = @id",
  ),
  getPending: db.prepare(
    "SELECT * FROM users WHERE status = 'pending' ORDER BY id DESC LIMIT 100",
  ),
  getAll: db.prepare("SELECT * FROM users ORDER BY id DESC"),
};

const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const genCode = customAlphabet(codeAlphabet, 8);
const genLogin = customAlphabet(codeAlphabet, 6);

function uniqueReferralCode() {
  let c;
  do {
    c = "DJ-" + genCode();
  } while (stmts.codeExists.get(c));
  return c;
}
function uniqueLoginId() {
  let i;
  do {
    i = "USR-" + genLogin();
  } while (stmts.loginIdExists.get(i));
  return i;
}

const MAINSTREAM_EMAILS = [
  "gmail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "icloud.com",
  "protonmail.com",
  "aol.com",
  "mail.com",
  "zoho.com",
  "yandex.com",
  "live.com",
  "msn.com",
];
function isValidEmail(e) {
  if (!e) return false;
  const p = e.trim().split("@");
  return p.length === 2 && MAINSTREAM_EMAILS.includes(p[1].toLowerCase());
}

// FIXED: Now accepts BTC, ETH, TRON, SOL, etc., matching the frontend
function isValidCryptoAddress(a) {
  if (!a || a.length < 20 || a.length > 100) return false;
  if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(a)) return true; // BTC Legacy
  if (/^bc1[ac-hj-np-zAC-HJ-NP-Z02-9]{11,71}$/.test(a)) return true; // BTC Bech32
  if (/^0x[a-fA-F0-9]{40}$/.test(a)) return true; // ETH/Polygon/BSC
  if (/^T[a-zA-HJ-NP-Z1-9]{33}$/.test(a)) return true; // TRON
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a)) return true; // SOL
  return /^[a-zA-Z0-9]{30,100}$/.test(a) && !a.includes(" "); // Fallback
}

const signupTx = db.transaction((d) => {
  const cur = stmts.count.get().c;
  if (cur >= CAPACITY) throw new Error("FULL");
  if (stmts.emailExists.get(d.email)) throw new Error("EXISTS");

  let refBy = null;
  if (d.refCode) {
    const n = d.refCode.trim().toUpperCase();
    if (stmts.referralValid.get(n)) refBy = n;
  }

  const login_id = uniqueLoginId();
  const referral_code = uniqueReferralCode();

  stmts.insert.run({
    login_id,
    email: d.email,
    usdt_address: d.usdt,
    token_address: d.token,
    referral_code,
    referred_by: refBy,
    quiz_answers: JSON.stringify(d.quiz || {}),
    fan_profile: JSON.stringify(d.fanProfile || {}),
    deposit_address_used: d.depositAddressUsed || "unknown",
    created_at: new Date().toISOString(),
  });

  return {
    login_id,
    referral_code,
    referred_by: refBy,
    spotsLeft: CAPACITY - (cur + 1),
  };
});

const app = express();

// Force MIME types for mobile video/webp
express.static.mime.define({
  "video/mp4": ["mp4", "m4v"],
  "video/webm": ["webm"],
  "image/webp": ["webp"],
});

app.use(
  helmet({
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
    hsts: false,
  }),
);

app.use(compression());
app.use(cors());
app.use(express.json({ limit: "100kb" }));
app.use(
  express.static(path.join(__dirname, "public"), { maxAge: "30d", etag: true }),
);
app.use(morgan("combined"));

// Security logging for admin routes
app.use((req, res, next) => {
  if (
    req.path.startsWith("/api/admin") &&
    req.headers["x-admin-key"] !== ADMIN_KEY
  ) {
    console.warn(
      `[SECURITY] Failed admin access attempt from IP: ${req.ip} at ${new Date().toISOString()}`,
    );
  }
  next();
});

// --- PUBLIC ROUTES ---
app.get("/api/status", (req, res) => {
  const c = stmts.count.get().c;
  res.json({
    capacity: CAPACITY,
    signedUp: c,
    spotsLeft: CAPACITY - c,
    isOpen: c < CAPACITY,
  });
});

app.get("/api/user/:loginId", (req, res) => {
  const user = stmts.getByLoginId.get(req.params.loginId);
  if (!user) return res.status(404).json({ error: "Not found" });
  res.json({
    loginId: user.login_id,
    referralCode: user.referral_code,
    status: user.status,
    notes: user.admin_notes,
  });
});

// --- RATE LIMITED SIGNUP ROUTE ---
const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // limit each IP to 3 signup attempts per 15 mins
  message: { error: "Too many signup attempts. Please wait 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post("/api/signup", signupLimiter, (req, res) => {
  try {
    const {
      email,
      usdtAddress,
      tokenAddress,
      referralCode,
      quizAnswers,
      fanProfile,
      depositAddressUsed,
    } = req.body;

    if (typeof quizAnswers !== "object" || quizAnswers === null)
      return res.status(400).json({ error: "Invalid quiz data format." });
    if (JSON.stringify(req.body).length > 5000)
      return res.status(400).json({ error: "Payload is too large." });
    if (!isValidEmail(email))
      return res
        .status(400)
        .json({ error: "Please enter a valid mainstream email address." });
    if (!isValidCryptoAddress(usdtAddress))
      return res.status(400).json({ error: "Invalid USDT wallet address." });
    if (!isValidCryptoAddress(tokenAddress))
      return res.status(400).json({ error: "Invalid token wallet address." });

    const result = signupTx({
      email: email.trim().toLowerCase(),
      usdt: usdtAddress.trim(),
      token: tokenAddress.trim(),
      refCode: referralCode,
      quiz: quizAnswers,
      fanProfile: fanProfile,
      depositAddressUsed: depositAddressUsed,
    });

    res.status(201).json({
      success: true,
      message: "Signup successful!",
      loginId: result.login_id,
      referralCode: result.referral_code,
      referredBy: result.referred_by,
      spotsLeft: result.spotsLeft,
    });
  } catch (e) {
    if (e.message === "FULL")
      return res.status(403).json({ error: "Signups are full." });
    if (e.message === "EXISTS")
      return res.status(409).json({ error: "Email already used." });
    console.error("Signup Error:", e);
    res.status(500).json({ error: "Something went wrong on our end." });
    // Note: In production, consider sending this error to a monitoring service like Sentry
  }
});

// --- ADMIN ROUTES ---
const requireAdmin = (req, res, next) => {
  if (req.headers["x-admin-key"] !== ADMIN_KEY)
    return res.status(401).json({ error: "Unauthorized" });
  next();
};

app.get("/api/admin/claims", requireAdmin, (req, res) => {
  const statusFilter = req.query.status || "pending";
  const users =
    statusFilter === "pending" ? stmts.getPending.all() : stmts.getAll.all();
  res.json(
    users.map((r) => ({
      ...r,
      quiz_answers: r.quiz_answers ? JSON.parse(r.quiz_answers) : null,
      fan_profile: r.fan_profile ? JSON.parse(r.fan_profile) : null,
    })),
  );
});

app.post("/api/admin/claims/:id/status", requireAdmin, (req, res) => {
  stmts.updateStatus.run({
    id: req.params.id,
    status: req.body.status,
    admin_notes: req.body.admin_notes || "",
  });
  res.json({ ok: true });
});

app.get("/api/admin/stats", requireAdmin, (req, res) => {
  const t = stmts.count.get().c;
  const p = db
    .prepare("SELECT COUNT(*) c FROM users WHERE status='pending'")
    .get().c;
  const paid = db
    .prepare("SELECT COUNT(*) c FROM users WHERE status='paid'")
    .get().c;
  res.json({ total: t, pending: p, paid: paid });
});

// FIXED: Real CSV Export for manual verification
app.get("/api/admin/export", requireAdmin, (req, res) => {
  const users = stmts.getAll.all();
  const headers = [
    "ID",
    "Login ID",
    "Email",
    "USDT Address",
    "Token Address",
    "Referral Code",
    "Referred By",
    "Status",
    "Admin Notes",
    "Used Deposit Address",
    "Created At",
  ];
  const csvRows = [headers.join(",")];

  for (const row of users) {
    const values = [
      row.id,
      row.login_id,
      `"${row.email}"`,
      `"${row.usdt_address}"`,
      `"${row.token_address}"`,
      row.referral_code,
      row.referred_by || "",
      row.status,
      `"${(row.admin_notes || "").replace(/"/g, '""')}"`, // Escape quotes for CSV
      row.deposit_address_used || "",
      row.created_at,
    ];
    csvRows.push(values.join(","));
  }

  res.setHeader("Content-Type", "text/csv");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename=claims_export_${new Date().toISOString().split("T")[0]}.csv`,
  );
  res.send("\uFEFF" + csvRows.join("\n")); // \uFEFF adds BOM for Excel compatibility
});

// --- SERVER START ---
// Check if SSL certs exist to decide between HTTP and HTTPS
const hasCerts = fs.existsSync("./cert.pem") && fs.existsSync("./key.pem");

if (hasCerts) {
  const httpsOptions = {
    key: fs.readFileSync("./key.pem"),
    cert: fs.readFileSync("./cert.pem"),
  };
  https.createServer(httpsOptions, app).listen(PORT, "0.0.0.0", () => {
    console.log(
      `\n🔒 SECURE SERVER RUNNING (HTTPS)\n Local: https://localhost:${PORT}\n Network: https://192.168.0.100:${PORT}\n Compression & 30-day caching enabled.\n`,
    );
  });
} else {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(
      `\n⚠️ HTTP SERVER RUNNING (No SSL certs found)\n Local: http://localhost:${PORT}\n Network: http://192.168.0.100:${PORT}\n`,
    );
  });
}
