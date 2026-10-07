/* ===================================================================
   Attira creator referral program
   Same-origin creator accounts, sessions, referral links, and analytics.
   Data shares the site's existing SQLite database so it follows the same
   persistence and backup path as the waitlist.
   =================================================================== */

const crypto = require("crypto");
const express = require("express");
const rateLimit = require("express-rate-limit");
const waitlist = require("./db");

const db = waitlist._db;
const router = express.Router();
const SESSION_DAYS = 30;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CODE_RE = /^[A-Z0-9]{7,18}$/;

db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS creators (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    creator_code TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active'
      CHECK(status IN ('active', 'paused', 'disabled')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS creator_sessions (
    token TEXT PRIMARY KEY,
    creator_id TEXT NOT NULL REFERENCES creators(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS creator_referral_clicks (
    id TEXT PRIMARY KEY,
    creator_id TEXT NOT NULL REFERENCES creators(id) ON DELETE CASCADE,
    click_id TEXT NOT NULL UNIQUE,
    creator_code TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT 'unknown'
      CHECK(platform IN ('android', 'ios', 'web', 'unknown')),
    user_agent TEXT NOT NULL DEFAULT '',
    utm_source TEXT NOT NULL DEFAULT '',
    utm_medium TEXT NOT NULL DEFAULT '',
    utm_campaign TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_creator_sessions_creator
    ON creator_sessions(creator_id);
  CREATE INDEX IF NOT EXISTS idx_creator_sessions_expiry
    ON creator_sessions(expires_at);
  CREATE INDEX IF NOT EXISTS idx_creator_clicks_creator_date
    ON creator_referral_clicks(creator_id, created_at);
`);

db.prepare("DELETE FROM creator_sessions WHERE datetime(expires_at) <= datetime('now')").run();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Please wait a few minutes and try again." },
});

const inviteLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many referral requests. Please try again shortly.",
});

function scrypt(password, salt, length) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, length, (error, key) => {
      if (error) reject(error);
      else resolve(key);
    });
  });
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const key = await scrypt(password, salt, 64);
  return `scrypt:${salt}:${key.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  const [algorithm, salt, expectedHex] = String(stored || "").split(":");
  if (algorithm !== "scrypt" || !salt || !expectedHex) return false;
  try {
    const expected = Buffer.from(expectedHex, "hex");
    const actual = await scrypt(password, salt, expected.length);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch (_) {
    return false;
  }
}

function cleanEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function generateCreatorCode(name) {
  const prefix = String(name || "")
    .replace(/[^a-z0-9]/gi, "")
    .toUpperCase()
    .slice(0, 6) || "CREATOR";
  return `${prefix}${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
}

function createSession(creatorId) {
  const token = crypto.randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
  const insert = db.transaction(() => {
    db.prepare("DELETE FROM creator_sessions WHERE creator_id = ?").run(creatorId);
    db.prepare("INSERT INTO creator_sessions (token, creator_id, expires_at) VALUES (?, ?, ?)")
      .run(token, creatorId, expiresAt);
  });
  insert();
  return token;
}

function requestOrigin(req) {
  return `${req.protocol}://${req.get("host")}`.replace(/\/$/, "");
}

function creatorPayload(req, creator) {
  return {
    id: creator.id,
    name: creator.name,
    email: creator.email,
    creator_code: creator.creator_code,
    status: creator.status,
    referral_link: `${requestOrigin(req)}/invite/${creator.creator_code}`,
    created_at: creator.created_at,
  };
}

function requireCreator(req, res, next) {
  const header = req.get("authorization") || "";
  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Creator login required" });
  }

  const session = db.prepare(`
    SELECT creator_id
      FROM creator_sessions
     WHERE token = ? AND datetime(expires_at) > datetime('now')
  `).get(header.slice(7));
  if (!session) return res.status(401).json({ error: "Invalid or expired creator session" });

  const creator = db.prepare("SELECT * FROM creators WHERE id = ? AND status = 'active'")
    .get(session.creator_id);
  if (!creator) return res.status(401).json({ error: "Creator account is unavailable" });
  req.creator = creator;
  return next();
}

function platformFor(userAgent) {
  if (/android/i.test(userAgent)) return "android";
  if (/iphone|ipad|ipod/i.test(userAgent)) return "ios";
  if (userAgent) return "web";
  return "unknown";
}

router.post("/api/creator/auth/signup", authLimiter, async (req, res, next) => {
  try {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    const email = cleanEmail(req.body.email);
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const confirmPassword = typeof req.body.confirmPassword === "string" ? req.body.confirmPassword : "";

    if (!name || name.length > 100) return res.status(400).json({ error: "Enter your name (up to 100 characters)." });
    if (!EMAIL_RE.test(email) || email.length > 254) return res.status(400).json({ error: "Enter a valid email address." });
    if (password.length < 8 || password.length > 200) return res.status(400).json({ error: "Password must be at least 8 characters." });
    if (password !== confirmPassword) return res.status(400).json({ error: "Passwords do not match." });
    if (db.prepare("SELECT 1 FROM creators WHERE email = ?").get(email)) {
      return res.status(409).json({ error: "A creator account already exists for this email." });
    }

    const id = crypto.randomUUID();
    const passwordHash = await hashPassword(password);
    let creatorCode = generateCreatorCode(name);
    while (db.prepare("SELECT 1 FROM creators WHERE creator_code = ?").get(creatorCode)) {
      creatorCode = generateCreatorCode(name);
    }
    db.prepare(`
      INSERT INTO creators (id, name, email, password_hash, creator_code)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, name, email, passwordHash, creatorCode);
    const creator = db.prepare("SELECT * FROM creators WHERE id = ?").get(id);
    return res.status(201).json({ creator: creatorPayload(req, creator), token: createSession(id) });
  } catch (error) {
    return next(error);
  }
});

router.post("/api/creator/auth/login", authLimiter, async (req, res, next) => {
  try {
    const email = cleanEmail(req.body.email);
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const creator = db.prepare("SELECT * FROM creators WHERE email = ?").get(email);
    if (!creator || !(await verifyPassword(password, creator.password_hash))) {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    if (creator.status !== "active") return res.status(403).json({ error: "This creator account is not active." });
    return res.json({ creator: creatorPayload(req, creator), token: createSession(creator.id) });
  } catch (error) {
    return next(error);
  }
});

router.delete("/api/creator/auth/session", (req, res) => {
  const header = req.get("authorization") || "";
  if (header.startsWith("Bearer ")) {
    db.prepare("DELETE FROM creator_sessions WHERE token = ?").run(header.slice(7));
  }
  res.status(204).end();
});

router.get("/api/creator/me", requireCreator, (req, res) => {
  res.json({ creator: creatorPayload(req, req.creator) });
});

router.get("/api/creator/analytics/clicks", requireCreator, (req, res) => {
  const range = String(req.query.range || "7d");
  const days = range === "7d" ? 7 : range === "30d" ? 30 : range === "90d" ? 90 : range === "all" ? null : undefined;
  if (days === undefined) return res.status(400).json({ error: "Range must be 7d, 30d, 90d, or all." });

  const oldest = days === null
    ? db.prepare("SELECT MIN(date(created_at)) AS date FROM creator_referral_clicks WHERE creator_id = ?").get(req.creator.id)
    : null;
  const start = days === null
    ? (oldest && oldest.date) || new Date().toISOString().slice(0, 10)
    : new Date(Date.now() - (days - 1) * 86400000).toISOString().slice(0, 10);
  const rows = db.prepare(`
    SELECT date(created_at) AS date, COUNT(*) AS clicks
      FROM creator_referral_clicks
     WHERE creator_id = ? AND date(created_at) >= date(?)
     GROUP BY date(created_at)
     ORDER BY date(created_at)
  `).all(req.creator.id, start);
  const counts = new Map(rows.map((row) => [row.date, Number(row.clicks)]));
  const end = new Date();
  const cursor = new Date(`${start}T00:00:00Z`);
  const points = [];
  while (cursor <= end) {
    const date = cursor.toISOString().slice(0, 10);
    points.push({ date, clicks: counts.get(date) || 0 });
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }
  return res.json({
    range,
    total_clicks: points.reduce((sum, point) => sum + point.clicks, 0),
    points,
  });
});

router.get("/invite/:creatorCode", inviteLimiter, (req, res) => {
  const creatorCode = String(req.params.creatorCode || "").trim().toUpperCase();
  if (!CODE_RE.test(creatorCode)) return res.status(404).send("Referral link not found");
  const creator = db.prepare("SELECT id, creator_code FROM creators WHERE creator_code = ? AND status = 'active'")
    .get(creatorCode);
  if (!creator) return res.status(404).send("Referral link not found");

  const userAgent = req.get("user-agent") || "";
  const clickId = crypto.randomUUID();
  db.prepare(`
    INSERT INTO creator_referral_clicks
      (id, click_id, creator_id, creator_code, platform, user_agent, utm_source, utm_medium, utm_campaign)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    crypto.randomUUID(),
    clickId,
    creator.id,
    creator.creator_code,
    platformFor(userAgent),
    userAgent.slice(0, 500),
    String(req.query.utm_source || "").slice(0, 200),
    String(req.query.utm_medium || "").slice(0, 200),
    String(req.query.utm_campaign || "").slice(0, 200)
  );

  const platform = platformFor(userAgent);
  const webUrl = process.env.ATTIRA_WEB_URL || `${requestOrigin(req)}/`;
  const androidUrl = process.env.ATTIRA_ANDROID_STORE_URL || "https://play.google.com/store/apps/details?id=com.tricore.attira";
  const iosUrl = process.env.ATTIRA_IOS_STORE_URL || "https://apps.apple.com/in/app/attira-outfit-planner/id6762454649";
  const destination = platform === "android" ? androidUrl : platform === "ios" ? iosUrl : webUrl;
  return res.redirect(302, destination);
});

module.exports = { router, platformFor };
