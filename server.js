/* ===================================================================
   Attira — web server + waitlist email capture
   Serves the static landing site AND exposes a small API that saves
   every "Get early access" email into the SQLite database (see db.js).

   Run it:   npm install   then   npm start
   Visit:    http://localhost:3000
   =================================================================== */

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const compression = require("compression");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const waitlist = require("./db");
const careers = require("./careers-db");
// The SAME module the browser loads for the careers form — so the form and
// this API validate against one spec instead of two copies that drift.
const roles = require("./careers-roles");
// One definition of "an application as a row", shared with the Drive index.
const xport = require("./careers-export");
const uploads = require("./careers-uploads");
const drive = require("./careers-drive");
const og = require("./og");
const creatorProgram = require("./creator-program");
const { PostHog } = require("posthog-node");

const posthog = new PostHog(process.env.POSTHOG_API_KEY, {
  host: process.env.POSTHOG_HOST || "https://us.i.posthog.com",
  enableExceptionAutocapture: true,
});

const PORT = parseInt(process.env.PORT || "3000", 10);
const STATIC_DIR = __dirname;
// Canonical public origin — used to build absolute URLs for link-unfurl OG
// tags and share-card images, which must point at attira.org regardless of
// the internal Cloud Run host the request actually lands on.
const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || "https://attira.org").replace(/\/+$/, "");
// Optional secret that protects the CSV export endpoint. If unset, the
// HTTP export route is disabled (you can still run `npm run export`).
const ADMIN_KEY = process.env.ADMIN_KEY || "";

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

/* ── Security headers (helmet) ──────────────────────────────────────
   CSP is tuned for this site: styles + the Google Fonts stylesheet,
   fonts from gstatic, images from self + data: URIs. Scripts are self
   only (the PostHog init is self-hosted in ph-init.js — no inline JS),
   with PostHog's asset CDN allowed so array.js can load and its capture
   endpoint allowed via connect-src. JSON-LD (<script type="application/
   ld+json">) is a data block, not executed, so it needs no allowance. */
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://us-assets.i.posthog.com"],
        "style-src": ["'self'", "https://fonts.googleapis.com"],
        "font-src": ["'self'", "https://fonts.gstatic.com"],
        "img-src": ["'self'", "data:"],
        // PostHog: load array.js from the asset CDN, send events to the API host.
        "connect-src": ["'self'", "https://us.i.posthog.com", "https://us-assets.i.posthog.com"],
        // posthog-js spins up a web worker from a blob: URL for batching.
        "worker-src": ["'self'", "blob:"],
        // contact.html submits via action="mailto:…", so allow the mailto scheme.
        "form-action": ["'self'", "mailto:"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "frame-ancestors": ["'none'"],
        "upgrade-insecure-requests": null,
      },
    },
    // HSTS is only meaningful over HTTPS; enable when deployed behind TLS.
    hsts: false,
    crossOriginEmbedderPolicy: false,
  })
);

/* ── Gzip/Brotli compression for text assets (html/css/js/json) ─── */
app.use(compression());

/* 64kb, not 16kb. A completed designer application is ~16,000 bytes of
   JSON in ASCII — already at the old ceiling — and every Devanagari
   character costs 3 bytes, so an applicant writing in Hindi blew straight
   past it at around 5,000 characters. The failure was silent and total:
   express replies with an HTML 413, the client's res.json() throws, and the
   applicant is told "network error" having lost every answer. */
app.use(express.json({ limit: "64kb" }));

/* Body-parser failures must come back as JSON, because that is what every
   fetch() on this site does with the response. Mounted immediately after
   the parser so it only sees parser errors. */
app.use((err, req, res, next) => {
  if (err && err.type === "entity.too.large") {
    return res.status(413).json({
      ok: false,
      error: "That's a lot of text — please shorten your longer answers a little and resubmit.",
    });
  }
  if (err && err.type === "entity.parse.failed") {
    return res.status(400).json({ ok: false, error: "We couldn't read that submission. Please try again." });
  }
  return next(err);
});

/* ── Rate limit the signup endpoint (anti-spam) ─────────────────── */
const signupLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler(req, res) {
    posthog.capture({
      distinctId: "anonymous",
      event: "waitlist_rate_limited",
      properties: { endpoint: "/api/waitlist", ip: req.ip },
    });
    res.status(429).json({ error: "Too many requests. Please slow down and try again shortly." });
  },
});

/* ── Rate limit job applications ─────────────────────────────────────
   Tighter than signups (a genuine applicant submits once) but not so tight
   that a shared IP locks people out: a campus lab or an office NAT can put
   several real applicants behind one address, and rejected submissions
   count toward the window too. Raised to 24 now that three roles are open:
   one person may legitimately apply for two of them, and the intern posting
   will draw student cohorts whose whole campus NATs to a single IP. Still
   useless for bulk spam — the endpoint demands a dozen valid fields. */
const applyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 24,
  standardHeaders: true,
  legacyHeaders: false,
  handler(req, res) {
    posthog.capture({
      distinctId: "anonymous",
      event: "careers_rate_limited",
      properties: { endpoint: "/api/careers/apply", ip: req.ip },
    });
    res.status(429).json({
      ok: false,
      error: "Too many applications from this connection. Please try again later.",
    });
  },
});

/* ── Email validation ───────────────────────────────────────────── */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function isValidEmail(v) {
  return typeof v === "string" && v.length <= 254 && EMAIL_RE.test(v);
}

/* ── Referral share-code validation ─────────────────────────────────
   Share codes look like ATR-XXXXX. Anything else is dropped silently so
   a typo'd or crafted ?ref= can never break a signup. */
const SHARE_CODE_RE = /^ATR-[A-Z0-9]{5}$/;
function sanitizeRef(v) {
  if (typeof v !== "string") return undefined;
  const code = v.trim().toUpperCase();
  return SHARE_CODE_RE.test(code) ? code : undefined;
}

/* ── Share-channel validation ───────────────────────────────────────
   The `c=` tag carried by referral links records which surface a referee
   came through. Whitelisted so it's safe to store and to break funnels by.
     wa WhatsApp · ig Instagram · tt TikTok · x X · dm direct message
     em email · cp copied link · other anything else explicitly tagged */
const CHANNELS = new Set(["wa", "ig", "tt", "x", "dm", "em", "cp", "other"]);
function sanitizeChannel(v) {
  if (typeof v !== "string") return undefined;
  const c = v.trim().toLowerCase().slice(0, 8);
  return CHANNELS.has(c) ? c : undefined;
}

/* ── UTM sanitisation ───────────────────────────────────────────── */
// Keep only known UTM keys and cap their length so a crafted request
// can't bloat events or the database.
const UTM_KEYS = ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"];
function sanitizeUtm(raw) {
  const out = {};
  if (!raw || typeof raw !== "object") return out;
  for (const key of UTM_KEYS) {
    const val = raw[key];
    if (typeof val === "string" && val.trim()) {
      out[key] = val.trim().slice(0, 200);
    }
  }
  return out;
}

/* ── Build the stats payload shared by signup + stats endpoints ────── */
function statsFor(shareCode, referralCount, createdAt, referredByCode) {
  return {
    shareCode,
    referralCount,
    position: waitlist.computePosition(referralCount, createdAt),
    total: waitlist.totalCount(),
    reward: waitlist.rewardFor(referralCount, referredByCode),
    leaderboard: waitlist.buildLeaderboard(),
  };
}

/* ── API: join the waitlist ─────────────────────────────────────── */
app.post("/api/waitlist", signupLimiter, (req, res) => {
  const { email } = req.body || {};
  const utm = sanitizeUtm(req.body && req.body.utm);
  const ref = sanitizeRef(req.body && req.body.ref);
  const channel = sanitizeChannel(req.body && req.body.channel);
  if (!isValidEmail(email)) {
    posthog.capture({
      distinctId: "anonymous",
      event: "waitlist_invalid_email",
      properties: { endpoint: "/api/waitlist" },
    });
    return res.status(400).json({ ok: false, error: "Please enter a valid email." });
  }
  try {
    const result = waitlist.addEmail({
      email,
      source: utm.utm_source || "website",
      userAgent: req.get("user-agent") || "",
      utm,
      ref,
      channel,
    });
    const distinctId = email.trim().toLowerCase();
    if (result.status === "created") {
      posthog.identify({
        distinctId,
        properties: {
          $set: { email: distinctId },
          $set_once: { waitlist_joined_at: new Date().toISOString() },
        },
      });
      posthog.capture({
        distinctId,
        event: "waitlist_signup",
        properties: {
          source: utm.utm_source || "website",
          ...utm,
          share_code: result.shareCode,
          referred_by: ref || null,
          share_channel: ref ? channel || null : null,
          $set: { email: distinctId },
        },
      });
    } else {
      posthog.capture({
        distinctId,
        event: "waitlist_signup_existing",
        properties: {
          source: utm.utm_source || "website",
          ...utm,
          share_code: result.shareCode,
          referral_count: result.referralCount,
        },
      });
    }
    // Re-read the row so position/referral_count reflect any same-request
    // bump (e.g. this very signup may have moved the referrer, not us).
    const row = waitlist.getByShareCode(result.shareCode);
    const stats = row
      ? statsFor(row.share_code, row.referral_count, row.created_at, row.referred_by_code)
      : { shareCode: result.shareCode, referralCount: result.referralCount, position: null, total: waitlist.totalCount(), reward: waitlist.rewardFor(result.referralCount, ref), leaderboard: waitlist.buildLeaderboard() };
    return res.json({
      ok: true,
      status: result.status,
      alreadyJoined: result.status === "existing",
      ...stats,
    });
  } catch (err) {
    console.error("waitlist insert failed:", err);
    posthog.captureException(err, undefined, { endpoint: "/api/waitlist" });
    posthog.capture({
      distinctId: "server",
      event: "waitlist_signup_failed",
      properties: { error: err && err.message, endpoint: "/api/waitlist" },
    });
    return res
      .status(500)
      .json({ ok: false, error: "Something went wrong. Please try again in a moment." });
  }
});

/* ── API: how many signups so far (handy to check it's working) ─── */
app.get("/api/waitlist/count", (req, res) => {
  res.json({ count: waitlist.totalCount() });
});

/* ── API: stats for one share code (powers the returning dashboard) ── */
app.get("/api/waitlist/stats", (req, res) => {
  const code = sanitizeRef(req.query.code);
  if (!code) return res.status(400).json({ ok: false, error: "Invalid code." });
  const row = waitlist.getByShareCode(code);
  if (!row) return res.status(404).json({ ok: false, error: "Not found." });
  res.json({ ok: true, ...statsFor(row.share_code, row.referral_count, row.created_at, row.referred_by_code) });
});

/* ── API: public stats (total + leaderboard) for first-time visitors ── */
app.get("/api/waitlist/public", (req, res) => {
  res.json({
    ok: true,
    total: waitlist.totalCount(),
    leaderboard: waitlist.buildLeaderboard(),
  });
});

/* ── API: public queue in signup order (powers /queue) ──────────────
   Masked emails only, paginated. Separate from the referral leaderboard. */
app.get("/api/waitlist/queue", (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 100;
  const offset = parseInt(req.query.offset, 10) || 0;
  res.json({ ok: true, ...waitlist.queue({ limit, offset }) });
});

/* ── Admin: download all emails as CSV ──────────────────────────────
   Gated by the ADMIN_KEY env var. Send it as ?key=... in the URL or as
   an `Authorization: Bearer <key>` header. Disabled when ADMIN_KEY unset. */
/* Shared with the careers export and the Drive index — it also neutralises
   formula-shaped cells, which matters the moment applicant-typed text is
   opened in Excel or Sheets. */
const csvEscape = xport.csvEscape;

function adminKeyMatches(req) {
  if (!ADMIN_KEY) return false;
  const header = req.get("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(header);
  const provided = m ? m[1] : req.query.key || "";
  if (!provided) return false;
  const a = Buffer.from(String(provided));
  const b = Buffer.from(ADMIN_KEY);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.get("/api/waitlist/export", (req, res) => {
  if (!adminKeyMatches(req)) return res.status(404).end();
  // Real signups only — seed rows are for public social proof, never outreach.
  const rows = waitlist.exportReal();
  posthog.capture({
    distinctId: "admin",
    event: "waitlist_export_accessed",
    properties: { row_count: rows.length },
  });
  const header =
    "id,email,source,utm_source,utm_medium,utm_campaign,user_agent," +
    "share_code,referred_by_code,referred_via_channel,referral_count,created_at\n";
  const body = rows
    .map((r) =>
      [
        r.id,
        r.email,
        r.source,
        r.utm_source,
        r.utm_medium,
        r.utm_campaign,
        r.user_agent,
        r.share_code,
        r.referred_by_code,
        r.referred_via_channel,
        r.referral_count,
        r.created_at,
      ]
        .map(csvEscape)
        .join(",")
    )
    .join("\n");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="attira-waitlist.csv"');
  res.send(header + body + "\n");
});

/* ===================================================================
   CAREERS — job application intake
   Applications land in a separate SQLite file (careers-db.js). Files are
   collected as LINKS in this pass (portfolio, artefacts, resume), so no
   object storage or multipart middleware is needed.

   Every question, option allowlist and format rule comes from
   careers-roles.js — the SAME module the browser loads. The form and this
   endpoint therefore reach identical verdicts by construction, instead of
   by two hand-maintained copies that drift.
   =================================================================== */

function clampStr(v, max) {
  if (typeof v !== "string") return "";
  return v.trim().slice(0, max || 5000);
}

/* Compensation arrives as a plain integer string (the client strips
   grouping separators). The cap rejects nonsense without second-guessing a
   genuinely large number. Returns undefined for "invalid". */
function parseComp(v) {
  if (v === null || v === undefined || v === "") return null;
  const n = typeof v === "number" ? v : parseInt(String(v).replace(/[^\d]/g, ""), 10);
  if (!Number.isFinite(n) || n < 0 || n > 1e9) return undefined;
  return n;
}

const CURRENCY_OPTIONS = new Set(roles.CURRENCIES.map((c) => c.value));

/* Normalise one submitted value to the shape validateField() and the DB
   expect. Never reads anything but the field the spec asked for. */
function normalizeValue(field, raw, body) {
  switch (field.type) {
    case "linklist": {
      const items = Array.isArray(raw) ? raw.slice(0, field.maxItems || roles.MAX_LINKS) : [];
      return items.map((l) => clampStr(l, 500)).filter(Boolean);
    }
    case "tags": {
      const picked = Array.isArray(raw) ? raw.slice(0, 30) : [];
      const allowed = roles.optionValues(field);
      return picked.map((t) => clampStr(t, 60)).filter((t) => allowed.indexOf(t) !== -1);
    }
    case "currency":
      return String(raw == null ? "" : raw).replace(/[^\d]/g, "");
    case "email":
      return clampStr(raw, field.maxlength || 254).toLowerCase();
    case "tel":
      return roles.normalizePhone(clampStr(raw, 40));
    case "url":
      return clampStr(raw, 500);
    /* The value of a file field is the opaque key /api/careers/upload
       handed back. Anything that isn't one of our keys is dropped to
       empty, so a crafted payload can't name an arbitrary object. */
    case "file":
      return uploads.isValidKey(raw) ? raw : "";
    default:
      return clampStr(raw, field.maxlength || 5000);
  }
}

/* ── Resume upload ───────────────────────────────────────────────────
   Files can't ride along in the apply payload (express.json caps the body
   at 64kb), so the browser posts the file the moment it's chosen and gets
   back an opaque key. The key is submitted with the rest of the answers
   and collected later by careers-drive.js.

   An unclaimed upload — someone who picks a file and never finishes — is
   simply never referenced by a row, and the bucket's lifecycle rule
   removes it. */
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler(req, res) {
    posthog.capture({
      distinctId: "anonymous",
      event: "careers_rate_limited",
      properties: { endpoint: "/api/careers/upload", ip: req.ip },
    });
    res.status(429).json({ ok: false, error: "Too many uploads. Please wait a minute and try again." });
  },
});

const uploadHandler = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1, fields: 4 },
}).single("file");

app.post("/api/careers/upload", uploadLimiter, (req, res) => {
  uploadHandler(req, res, async (err) => {
    if (err) {
      const tooBig = err.code === "LIMIT_FILE_SIZE";
      return res.status(tooBig ? 413 : 400).json({
        ok: false,
        error: tooBig
          ? "That file is over 10MB — please upload a smaller PDF."
          : "We couldn't read that upload. Please try again.",
      });
    }
    if (!req.file || !req.file.buffer || !req.file.buffer.length) {
      return res.status(400).json({ ok: false, error: "No file was received." });
    }

    // The browser's Content-Type is a claim; the magic bytes are evidence.
    const sniffed = uploads.sniff(req.file.buffer);
    if (!sniffed) {
      return res.status(415).json({
        ok: false,
        error: "Please upload a PDF, Word document, or an image of your resume.",
      });
    }

    try {
      const key = await uploads.putStaged(req.file.buffer, {
        contentType: sniffed.contentType,
        originalName: req.file.originalname,
      });
      posthog.capture({
        distinctId: "anonymous",
        event: "career_resume_uploaded",
        properties: { bytes: req.file.buffer.length, content_type: sniffed.contentType },
      });
      return res.json({
        ok: true,
        token: key,
        filename: String(req.file.originalname || "resume").slice(0, 120),
        bytes: req.file.buffer.length,
      });
    } catch (uploadErr) {
      console.error("resume upload failed:", uploadErr);
      posthog.captureException(uploadErr, undefined, { endpoint: "/api/careers/upload" });
      return res.status(500).json({
        ok: false,
        error: "We couldn't store that file. You can paste a link to it instead.",
      });
    }
  });
});

app.post("/api/careers/apply", applyLimiter, (req, res) => {
  const b = req.body || {};
  const fail = (error) => {
    posthog.capture({
      distinctId: "anonymous",
      event: "career_application_invalid",
      properties: { endpoint: "/api/careers/apply", reason: error },
    });
    return res.status(400).json({ ok: false, error });
  };

  const role = roles.findRole(typeof b.role === "string" ? b.role : "");
  if (!role) return fail("That role isn't open.");

  const submitted = (b.fields && typeof b.fields === "object") ? b.fields : {};
  const answers = {};

  /* Walk the SPEC, not the request body. A crafted key cannot enter because
     nothing here ever reads Object.keys(submitted). showIf is evaluated
     against the answers gathered so far, so a conditional question the
     applicant never saw is not demanded of them — the same rule the form
     applies on screen. */
  for (const step of role.steps) {
    for (const field of step.fields) {
      if (typeof field.showIf === "function" && !field.showIf(answers)) continue;

      const value = normalizeValue(field, submitted[field.name], submitted);
      if (field.type === "tags") {
        answers[field.name + "Other"] = clampStr(submitted[field.name + "Other"], 200);
      }

      const msg = roles.validateField(field, value, answers);
      if (msg) return fail(msg);

      answers[field.name] = value;
    }
  }

  const compCurrency = CURRENCY_OPTIONS.has(b.fields && b.fields.compCurrency)
    ? b.fields.compCurrency
    : "INR";
  const currentComp = parseComp(answers.currentComp);
  const expectedComp = parseComp(answers.expectedComp);
  if (currentComp === undefined || expectedComp === undefined) {
    return fail("Please enter a valid compensation amount.");
  }

  const utm = sanitizeUtm(b.utm);

  /* Columns the table holds directly; everything else in the spec goes to
     the answers JSON blob. Derived from the spec, so a new role needs no
     change here. */
  const COMMON = new Set([
    "fullName", "email", "phone", "location", "resumeUrl", "resumeFile",
    "anythingElse", "currentComp", "expectedComp",
  ]);
  const roleAnswers = {};
  for (const field of roles.fieldsFor(role.id)) {
    if (COMMON.has(field.name)) continue;
    if (!(field.name in answers)) continue;
    roleAnswers[field.name] = answers[field.name];
    if (field.type === "tags") roleAnswers[field.name + "Other"] = answers[field.name + "Other"];
  }

  try {
    // Built from a fixed column list, never from Object.keys(req.body) — the
    // client cannot introduce a column or overwrite one it shouldn't.
    const result = careers.addApplication({
      role: role.id,
      full_name: answers.fullName,
      email: answers.email,
      phone: answers.phone || null,
      location: answers.location || null,
      resume_url: answers.resumeUrl || null,
      current_comp: currentComp === null ? null : currentComp,
      expected_comp: expectedComp === null ? null : expectedComp,
      comp_currency: compCurrency,
      anything_else: answers.anythingElse || null,
      answers: JSON.stringify(roleAnswers),
      user_agent: (req.get("user-agent") || "").slice(0, 255),
      utm_source: utm.utm_source || null,
      // normalizeValue has already rejected anything that isn't one of our
      // staged upload keys.
      file_keys: answers.resumeFile ? JSON.stringify([answers.resumeFile]) : null,
    });

    posthog.capture({
      distinctId: answers.email,
      event: "career_application_received",
      properties: {
        role: role.id,
        ref: result.ref,
        field_count: Object.keys(answers).length,
        utm_source: utm.utm_source || null,
      },
    });
    // Structured single-line log so a GCP log-based alert can notify on
    // jsonPayload.event without any further code change.
    console.log(JSON.stringify({
      event: "career_application", ref: result.ref, role: role.id, email: answers.email,
    }));

    res.json({ ok: true, ref: result.ref });

    /* Mirror to Drive AFTER the applicant has their reference — a Drive
       outage must never turn into a failed submission. This kick is
       best-effort: Cloud Run throttles CPU once the response is sent, so
       the guaranteed path is the Cloud Scheduler call to
       /api/careers/sync-drive, which runs inside a request. */
    setImmediate(() => {
      drive.syncPending({ limit: 5 }).catch((err) => {
        console.error("[careers-drive] post-submit sync failed:", err.message);
      });
    });
    return;
  } catch (err) {
    console.error("career application insert failed:", err);
    posthog.captureException(err, undefined, { endpoint: "/api/careers/apply" });
    return res.status(500).json({
      ok: false,
      error: "Something went wrong saving your application. Please try again in a moment.",
    });
  }
});

/* ── Admin: applications as CSV / JSON ──────────────────────────────
   Same gate as the waitlist export — ADMIN_KEY via ?key= or a Bearer
   header, 404 (not 403) when unset so the route is invisible. */

app.get("/api/careers/export", (req, res) => {
  if (!adminKeyMatches(req)) return res.status(404).end();

  const roleId = typeof req.query.role === "string" && req.query.role ? req.query.role : null;
  const role = roleId ? roles.findRole(roleId) : null;
  // 400 rather than 404: adminKeyMatches already owns 404 for "not
  // authorised", so reusing it here would be ambiguous.
  if (roleId && !role) return res.status(400).json({ ok: false, error: "Unknown role." });

  const rows = careers.exportAll(roleId);
  posthog.capture({
    distinctId: "admin",
    event: "careers_export_accessed",
    properties: { row_count: rows.length, role: roleId },
  });

  /* Role-filtered: one column per question, in the order they were asked,
     so the CSV reads as a transcript of the form. Without a role: common
     columns plus the raw blob, so nothing is unreachable in an export
     whose rows answer different questions. Both shapes come from
     careers-export.js, which the Drive index also uses. */
  const csv = xport.toCsv(
    xport.headerFor(roleId),
    rows.map((r) => xport.rowFor(roleId, r))
  );

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="attira-applications${roleId ? "-" + roleId : ""}.csv"`
  );
  // BOM: these exports contain ₹, en-dashes and curly quotes, all of which
  // Excel mangles without it. (The waitlist export is left untouched.)
  res.send("﻿" + csv);
});

/* ── Admin: drain the Drive mirror queue ─────────────────────────────
   The reliable trigger. Cloud Scheduler POSTs here every 5 minutes with
   the ADMIN_KEY bearer header; because the work happens inside a request,
   Cloud Run guarantees CPU for it (outside a request it is throttled, so
   a bare setInterval would stall). Safe to call by hand at any time —
   syncPending() is idempotent and coalesces concurrent runs. */
app.post("/api/careers/sync-drive", async (req, res) => {
  if (!adminKeyMatches(req)) return res.status(404).end();
  if (!drive.isConfigured()) {
    return res.status(503).json({ ok: false, error: "DRIVE_OAUTH is not configured." });
  }
  const limit = Math.min(50, parseInt(req.query.limit, 10) || 20);
  try {
    const summary = await drive.syncPending({ limit });
    return res.json({ ok: true, ...summary });
  } catch (err) {
    console.error("drive sync failed:", err);
    posthog.captureException(err, undefined, { endpoint: "/api/careers/sync-drive" });
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/careers/applications", (req, res) => {
  if (!adminKeyMatches(req)) return res.status(404).end();
  const roleId = typeof req.query.role === "string" && req.query.role ? req.query.role : null;
  if (roleId && !roles.findRole(roleId)) {
    return res.status(400).json({ ok: false, error: "Unknown role." });
  }
  const limit = parseInt(req.query.limit, 10) || 50;
  const offset = parseInt(req.query.offset, 10) || 0;
  res.json({ ok: true, ...careers.listApplications({ role: roleId, limit, offset }) });
});

/* ── HTML-escape helper for the unfurl page's interpolated values ── */
function htmlEscape(v) {
  return String(v == null ? "" : v).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

/* ── Dynamic OG card image for a referral code ──────────────────────
   Served same-origin (CSP img-src 'self' already allows it). Falls back
   to the static brand image so a render failure never breaks an unfurl. */
app.get("/api/og/:code.png", async (req, res) => {
  const code = sanitizeRef(req.params.code);
  if (!code) return res.redirect(302, "/assets/og-image.png");
  try {
    const row = waitlist.getByShareCode(code);
    if (!row) return res.redirect(302, "/assets/og-image.png");
    const png = await og.renderCard({
      code,
      position: waitlist.computePosition(row.referral_count, row.created_at),
      referralCount: row.referral_count,
    });
    res.setHeader("Content-Type", "image/png");
    // Position can change as friends join, so cache only briefly.
    res.setHeader("Cache-Control", "public, max-age=300");
    res.send(png);
  } catch (err) {
    console.error("og render failed:", err && err.message);
    posthog.captureException(err, undefined, { endpoint: "/api/og" });
    res.redirect(302, "/assets/og-image.png");
  }
});

/* ── Referral short links: /r/ATR-XXXXX ─────────────────────────────
   Registered before the static handler so it isn't shadowed by a file.

   Serves a tiny HTML shell carrying PER-REFERRER OG tags (so the link
   unfurls personally in WhatsApp/iMessage/X) and immediately bounces a
   real browser on to /?ref=CODE&c=CHANNEL via meta-refresh + JS. Crawlers
   read the static <meta>; humans never see the page. Falls back to a
   plain redirect for invalid/unknown codes. The optional ?c= tag records
   which share surface the click came from. */
app.get("/r/:code", (req, res) => {
  const code = sanitizeRef(req.params.code);
  const channel = sanitizeChannel(req.query.c);
  if (!code) return res.redirect(302, "/");

  const dest = `/?ref=${code}${channel ? `&c=${channel}` : ""}`;
  const row = waitlist.getByShareCode(code);
  if (!row) return res.redirect(302, dest); // unknown code → still let them join

  const position = waitlist.computePosition(row.referral_count, row.created_at);
  const title = `Join the Attira waitlist — skip ahead together`;
  const desc = position
    ? `Your friend is #${position.toLocaleString()} in line. Join with their link and you both move up the queue.`
    : `Join with your friend's link and you both move up the queue.`;
  const ogImg = `${PUBLIC_ORIGIN}/api/og/${code}.png`;
  const canonical = `${PUBLIC_ORIGIN}${dest}`;

  res.setHeader("Cache-Control", "no-cache");
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="robots" content="noindex, nofollow" />
<title>${htmlEscape(title)}</title>
<meta name="description" content="${htmlEscape(desc)}" />
<meta property="og:type" content="website" />
<meta property="og:site_name" content="Attira" />
<meta property="og:title" content="${htmlEscape(title)}" />
<meta property="og:description" content="${htmlEscape(desc)}" />
<meta property="og:url" content="${htmlEscape(canonical)}" />
<meta property="og:image" content="${htmlEscape(ogImg)}" />
<meta property="og:image:width" content="${og.WIDTH}" />
<meta property="og:image:height" content="${og.HEIGHT}" />
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:title" content="${htmlEscape(title)}" />
<meta name="twitter:description" content="${htmlEscape(desc)}" />
<meta name="twitter:image" content="${htmlEscape(ogImg)}" />
<meta http-equiv="refresh" content="0; url=${htmlEscape(dest)}" />
<link rel="canonical" href="${htmlEscape(canonical)}" />
</head>
<body>
<p>Redirecting you to the Attira waitlist… <a href="${htmlEscape(dest)}">Continue</a></p>
<script>location.replace(${JSON.stringify(dest)});</script>
</body>
</html>`);
});

/* ── Creator referral program ─────────────────────────────────────
   Account, dashboard analytics, and tracked /invite/:code links now
   live on the main Attira origin instead of a separate application. */
app.use(creatorProgram.router);

/* ── Static landing site (index.html, legal pages, assets, …) ───── */
app.use(
  express.static(STATIC_DIR, {
    extensions: ["html"],
    setHeaders(res, filePath) {
      if (/\.html$/.test(filePath)) {
        // markup must always revalidate so new ?v= asset references are picked up
        res.setHeader("Cache-Control", "no-cache");
      } else if (/\.(css|js)$/.test(filePath)) {
        // css/js are ?v=-versioned in the HTML → safe to cache hard (1 year)
        res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
      } else {
        // images / fonts / other static assets — cache a week
        res.setHeader("Cache-Control", "public, max-age=604800");
      }
    },
  })
);

app.get("/", (req, res) => res.sendFile(path.join(STATIC_DIR, "index.html")));

/* ── Start ──────────────────────────────────────────────────────── */
const server = app.listen(PORT, () => {
  console.log(`\nAttira site + waitlist running →  http://localhost:${PORT}`);
  console.log(`Emails are saved to: ${waitlist.DB_PATH}`);
  console.log(`Applications are saved to: ${careers.DB_PATH}`);
  console.log(`Export anytime with:  npm run export\n`);
  if (!ADMIN_KEY) {
    console.warn("[note] ADMIN_KEY not set — the /api/waitlist/export and /api/careers/* admin URLs are disabled (use `npm run export`).");
  }
  if (drive.isConfigured()) {
    console.log(`Applications also mirror to Google Drive → "${drive.ROOT_FOLDER_NAME}"`);
  } else {
    console.warn("[note] DRIVE_OAUTH not set — applications save normally but stay 'pending' for the Drive mirror.");
  }
  /* Loud, because the failure is silent otherwise: with no bucket, staged
     resumes go to DATA_DIR, which on Cloud Run is an in-memory filesystem.
     They'd count against the 512Mi limit and vanish on the next revision,
     losing a file the applicant was already told we had. */
  if (process.env.NODE_ENV === "production" && !uploads.usingGcs()) {
    console.error(
      "[WARNING] DRIVE_UPLOAD_BUCKET is not set. Uploaded resumes will be staged on the " +
      "container's ephemeral filesystem and LOST on the next deploy. Set it to the GCS bucket."
    );
  }
});

function shutdown() {
  server.close(async () => {
    try { waitlist._db.close(); } catch (_) {}
    try { careers._db.close(); } catch (_) {}
    await posthog.shutdown();
    process.exit(0);
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
