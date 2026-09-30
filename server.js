require("dotenv").config();
const crypto = require("crypto");
const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const QRCode = require("qrcode");

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const SALT = process.env.HASH_SALT || "change-moi";
const TZ = process.env.TZ_STATS || "Indian/Antananarivo";
const JWT_SECRET = process.env.JWT_SECRET;
const REQUIRE_LOGIN = process.env.REQUIRE_LOGIN === "true";
const SB_KEY = process.env.SAFE_BROWSING_KEY;
const IS_PROD = process.env.NODE_ENV === "production";
const ADMINS = (process.env.ADMIN_EMAILS || "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
const REPORT_THRESHOLD = 3; // signalements distincts avant désactivation automatique
const DAY = 864e5;

if (!JWT_SECRET) { console.error("JWT_SECRET manquant dans .env"); process.exit(1); }

app.set("trust proxy", 1);
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

/* ---------- Modèles ---------- */
const User = mongoose.model("User", new mongoose.Schema(
  { email: { type: String, required: true, unique: true }, passwordHash: { type: String, required: true } },
  { timestamps: true }
));

const Link = mongoose.model("Link", new mongoose.Schema(
  {
    code: { type: String, required: true, unique: true },
    url: { type: String, required: true },
    owner: { type: String, index: true, default: null }, // "u:<userId>" ou jeton anonyme
    clicks: { type: Number, default: 0 },
    expiresAt: { type: Date, default: null },
    disabled: { type: Boolean, default: false },
  },
  { timestamps: true }
));

const Click = mongoose.model("Click", new mongoose.Schema({
  code: { type: String, required: true },
  at: { type: Date, default: Date.now },
  visitor: String, referrer: String, device: String, browser: String, os: String, country: String,
}).index({ code: 1, at: -1 }));

const Report = mongoose.model("Report", new mongoose.Schema({
  code: { type: String, required: true },
  reporter: { type: String, required: true },
  reason: { type: String, default: "" },
  at: { type: Date, default: Date.now },
}).index({ code: 1, reporter: 1 }, { unique: true }));

/* ---------- Utilitaires ---------- */
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const RESERVED = new Set(["api", "stats", "p", "admin", "admin.html", "index", "index.html", "stats.html", "preview.html", "404.html", "style.css", "favicon.ico"]);
const randomCode = (len = 6) => Array.from(crypto.randomBytes(len), (b) => ALPHABET[b % ALPHABET.length]).join("");
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 16);
const dayKey = (t) => new Date(t).toLocaleDateString("sv-SE", { timeZone: TZ });

/* ----- Sécurité des URL ----- */
const BUILTIN_BLOCKED = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "t.ly"];
const BLOCKED = [...BUILTIN_BLOCKED, ...(process.env.BLOCKED_DOMAINS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean)];
const hostBlocked = (h) => BLOCKED.some((d) => h === d || h.endsWith("." + d));

function checkUrl(input) {
  let value = String(input || "").trim();
  if (!value) return { error: "Colle un lien à raccourcir." };
  if (value.length > 2048) return { error: "Lien trop long." };
  if (!/^https?:\/\//i.test(value)) value = "https://" + value;
  let u;
  try { u = new URL(value); } catch { return { error: "Lien invalide." }; }
  if (!["http:", "https:"].includes(u.protocol)) return { error: "Lien invalide." };
  if (u.username || u.password) return { error: "Les liens avec identifiants ne sont pas acceptés." };
  const host = u.hostname.toLowerCase();
  if (!host.includes(".") || host.startsWith("[") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host))
    return { error: "Utilise un nom de domaine (pas d'adresse IP ni de localhost)." };
  if (u.origin === new URL(BASE_URL).origin) return { error: "Impossible de raccourcir un lien de ce site." };
  if (hostBlocked(host)) return { error: "Ce domaine n'est pas accepté." };
  return { url: u.toString() };
}

async function isUnsafe(url) {
  if (!SB_KEY) return false;
  try {
    const r = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SB_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(4000),
      body: JSON.stringify({
        client: { clientId: "shortlink", clientVersion: "2.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    });
    const d = await r.json();
    return Boolean(d.matches && d.matches.length);
  } catch (e) {
    console.warn("Safe Browsing indisponible :", e.message);
    return false;
  }
}

/* ----- Détection navigateur ----- */
const BOT_RE = /bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegram|discord|curl|wget|python-requests|headless|monitor|uptime/i;
function parseUA(ua = "") {
  const device = /ipad|tablet/i.test(ua) ? "Tablette" : /mobi|android|iphone/i.test(ua) ? "Mobile" : "Ordinateur";
  const browser = /edg\//i.test(ua) ? "Edge" : /opr\/|opera/i.test(ua) ? "Opera" : /firefox|fxios/i.test(ua) ? "Firefox"
    : /chrome|crios/i.test(ua) ? "Chrome" : /safari/i.test(ua) ? "Safari" : "Autre";
  const os = /windows/i.test(ua) ? "Windows" : /android/i.test(ua) ? "Android" : /iphone|ipad|ios/i.test(ua) ? "iOS"
    : /mac os/i.test(ua) ? "macOS" : /linux/i.test(ua) ? "Linux" : "Autre";
  return { device, browser, os };
}
function referrerHost(req) {
  const ref = req.get("referer");
  if (!ref) return "Direct";
  try { return new URL(ref).hostname.replace(/^www\./, "") || "Direct"; } catch { return "Direct"; }
}

/* ----- Session ----- */
app.use((req, res, next) => {
  const t = req.cookies && req.cookies.token;
  if (t) { try { req.userId = jwt.verify(t, JWT_SECRET).sub; } catch { /* jeton invalide */ } }
  next();
});
const anonOwner = (req) => {
  const o = String(req.get("x-owner") || "");
  return /^[\w-]{16,64}$/.test(o) ? o : null;
};
const getOwner = (req) => (req.userId ? "u:" + req.userId : anonOwner(req));

function setSession(res, user) {
  const token = jwt.sign({ sub: String(user._id) }, JWT_SECRET, { expiresIn: "30d" });
  res.cookie("token", token, { httpOnly: true, sameSite: "lax", secure: IS_PROD, maxAge: 30 * DAY });
}
async function adoptAnonLinks(req, user) {
  const anon = anonOwner(req);
  if (anon) await Link.updateMany({ owner: anon }, { owner: "u:" + user._id });
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
  message: { error: "Trop de tentatives, réessaie dans quelques minutes." },
});
const shortenLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: (req) => (req.userId ? 60 : 10), standardHeaders: true, legacyHeaders: false,
  message: { error: "Trop de liens créés, réessaie dans quelques minutes (ou connecte-toi)." },
});
const reportLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: { error: "Trop de signalements, réessaie plus tard." },
});

/* ---------- API : comptes ---------- */
app.post("/api/auth/register", authLimiter, wrap(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Email invalide." });
  if (password.length < 8 || password.length > 72) return res.status(400).json({ error: "Mot de passe : 8 à 72 caractères." });
  if (await User.exists({ email })) return res.status(409).json({ error: "Un compte existe déjà avec cet email." });
  const user = await User.create({ email, passwordHash: await bcrypt.hash(password, 10) });
  await adoptAnonLinks(req, user);
  setSession(res, user);
  res.status(201).json({ email });
}));

app.post("/api/auth/login", authLimiter, wrap(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: "Email ou mot de passe incorrect." });
  await adoptAnonLinks(req, user);
  setSession(res, user);
  res.json({ email });
}));

app.post("/api/auth/logout", (req, res) => { res.clearCookie("token"); res.json({ ok: true }); });

app.get("/api/auth/me", wrap(async (req, res) => {
  const user = req.userId ? await User.findById(req.userId).select("email").lean() : null;
  if (req.userId && !user) res.clearCookie("token");
  res.json({ email: user ? user.email : null, admin: Boolean(user && ADMINS.includes(user.email)) });
}));

/* ---------- API : liens ---------- */
app.post("/api/shorten", shortenLimiter, wrap(async (req, res) => {
  if (REQUIRE_LOGIN && !req.userId) return res.status(401).json({ error: "Connecte-toi pour créer un lien." });

  const checked = checkUrl(req.body.url);
  if (checked.error) return res.status(400).json({ error: checked.error });
  const url = checked.url;
  if (await isUnsafe(url)) return res.status(400).json({ error: "Ce lien est signalé comme dangereux et ne peut pas être raccourci." });

  let code = String(req.body.alias || "").trim();
  if (code) {
    if (!/^[a-zA-Z0-9_-]{3,30}$/.test(code) || RESERVED.has(code.toLowerCase()))
      return res.status(400).json({ error: "Alias invalide (3-30 caractères : lettres, chiffres, - _)." });
    if (await Link.exists({ code })) return res.status(409).json({ error: "Cet alias est déjà pris." });
  } else {
    for (let i = 0; i < 5; i++) {
      const c = randomCode();
      if (!(await Link.exists({ code: c }))) { code = c; break; }
    }
    if (!code) return res.status(500).json({ error: "Impossible de générer un code, réessaie." });
  }

  const days = Number(req.body.expiresInDays);
  const expiresAt = [1, 7, 30].includes(days) ? new Date(Date.now() + days * DAY) : null;
  try {
    await Link.create({ code, url, owner: getOwner(req), expiresAt });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: "Cet alias est déjà pris." });
    throw e;
  }
  res.status(201).json({ code, shortUrl: `${BASE_URL}/${code}`, url, expiresAt });
}));

app.get("/api/my-links", wrap(async (req, res) => {
  const owner = getOwner(req);
  if (!owner) return res.json([]);
  const links = await Link.find({ owner }).sort({ createdAt: -1 }).limit(200).lean();
  res.json(links.map((l) => ({
    code: l.code, url: l.url, shortUrl: `${BASE_URL}/${l.code}`, clicks: l.clicks,
    createdAt: l.createdAt, expiresAt: l.expiresAt, disabled: l.disabled,
  })));
}));

app.delete("/api/links/:code", wrap(async (req, res) => {
  const owner = getOwner(req);
  const link = owner && (await Link.findOneAndDelete({ code: req.params.code, owner }));
  if (!link) return res.status(404).json({ error: "Lien introuvable." });
  await Promise.all([Click.deleteMany({ code: link.code }), Report.deleteMany({ code: link.code })]);
  res.json({ ok: true });
}));

app.get("/api/qr/:code", wrap(async (req, res) => {
  const code = req.params.code;
  if (!(await Link.exists({ code }))) return res.status(404).json({ error: "Lien introuvable." });
  const text = `${BASE_URL}/${code}`;
  const svg = req.query.format === "svg";
  if (req.query.download) res.set("Content-Disposition", `attachment; filename="qr-${code}.${svg ? "svg" : "png"}"`);
  res.set("Cache-Control", "public, max-age=86400");
  if (svg) return res.type("image/svg+xml").send(await QRCode.toString(text, { type: "svg", margin: 2 }));
  res.type("image/png").send(await QRCode.toBuffer(text, { width: 600, margin: 2 }));
}));

/* ---------- API : aperçu et signalement ---------- */
app.get("/api/preview/:code", wrap(async (req, res) => {
  const link = await Link.findOne({ code: req.params.code }).lean();
  const gone = !link || link.disabled || (link.expiresAt && link.expiresAt < new Date());
  if (gone) return res.status(link ? 410 : 404).json({ error: "Ce lien n'existe pas, a expiré ou a été désactivé." });
  res.json({ code: link.code, url: link.url, host: new URL(link.url).hostname });
}));

app.post("/api/report", reportLimiter, wrap(async (req, res) => {
  const code = String(req.body.code || "");
  const link = await Link.findOne({ code });
  if (!link) return res.status(404).json({ error: "Lien introuvable." });
  const reporter = sha(SALT + req.ip + (req.get("user-agent") || ""));
  try {
    await Report.create({ code, reporter, reason: String(req.body.reason || "").slice(0, 200) });
  } catch (e) { if (e.code !== 11000) throw e; }
  const n = await Report.countDocuments({ code });
  if (n >= REPORT_THRESHOLD && !link.disabled) {
    link.disabled = true;
    await link.save();
    console.warn(`Lien /${code} désactivé après ${n} signalements : ${link.url}`);
  }
  res.json({ ok: true });
}));

/* ---------- API : stats ---------- */
app.get("/api/stats/:code", wrap(async (req, res) => {
  const { code } = req.params;
  const link = await Link.findOne({ code }).lean();
  if (!link) return res.status(404).json({ error: "Lien introuvable." });
  if (link.owner && link.owner !== getOwner(req))
    return res.status(403).json({ error: "Les statistiques sont réservées au propriétaire du lien." });

  const now = Date.now();
  const since30 = new Date(now - 30 * DAY);
  const group = (field) => Click.aggregate([
    { $match: { code } },
    { $group: { _id: `$${field}`, count: { $sum: 1 } } },
    { $sort: { count: -1 } },
    { $limit: 8 },
  ]).then((rows) => rows.map((r) => ({ label: r._id || "Inconnu", count: r.count })));

  const [uniq, daily, last24h, last7d, referrers, devices, browsers, os, countries, recent] = await Promise.all([
    Click.aggregate([{ $match: { code } }, { $group: { _id: "$visitor" } }, { $count: "n" }]),
    Click.aggregate([
      { $match: { code, at: { $gte: since30 } } },
      { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$at", timezone: TZ } }, count: { $sum: 1 } } },
    ]),
    Click.countDocuments({ code, at: { $gte: new Date(now - DAY) } }),
    Click.countDocuments({ code, at: { $gte: new Date(now - 7 * DAY) } }),
    group("referrer"), group("device"), group("browser"), group("os"), group("country"),
    Click.find({ code }).sort({ at: -1 }).limit(20).select("at referrer device browser os country -_id").lean(),
  ]);

  const byDay = new Map(daily.map((d) => [d._id, d.count]));
  const series = [];
  for (let i = 29; i >= 0; i--) { const date = dayKey(now - i * DAY); series.push({ date, count: byDay.get(date) || 0 }); }

  res.json({
    code, url: link.url, shortUrl: `${BASE_URL}/${code}`, createdAt: link.createdAt, expiresAt: link.expiresAt,
    disabled: link.disabled, total: link.clicks, uniques: uniq[0] ? uniq[0].n : 0, last24h, last7d,
    daily: series, referrers, devices, browsers, os, countries, recent,
  });
}));

/* ---------- API : administration ---------- */
const requireAdmin = wrap(async (req, res, next) => {
  const user = req.userId ? await User.findById(req.userId).select("email").lean() : null;
  if (!user || !ADMINS.includes(user.email)) return res.status(403).json({ error: "Accès réservé aux administrateurs." });
  next();
});
const escapeRe = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const safeHost = (u) => { try { return new URL(u).hostname; } catch { return ""; } };
const adminRow = (l, extra = {}) => ({
  code: l.code, url: l.url, host: safeHost(l.url), clicks: l.clicks, createdAt: l.createdAt,
  disabled: l.disabled, hasAccount: Boolean(l.owner && l.owner.startsWith("u:")), ...extra,
});

app.get("/api/admin/overview", requireAdmin, wrap(async (req, res) => {
  const [users, links, disabled, reported, clicks] = await Promise.all([
    User.countDocuments(), Link.countDocuments(), Link.countDocuments({ disabled: true }),
    Report.distinct("code"), Link.aggregate([{ $group: { _id: null, n: { $sum: "$clicks" } } }]),
  ]);
  res.json({ users, links, disabled, reported: reported.length, clicks: clicks[0] ? clicks[0].n : 0 });
}));

app.get("/api/admin/reports", requireAdmin, wrap(async (req, res) => {
  const groups = await Report.aggregate([
    { $group: { _id: "$code", count: { $sum: 1 }, last: { $max: "$at" }, reasons: { $push: "$reason" } } },
    { $sort: { count: -1, last: -1 } },
    { $limit: 100 },
  ]);
  const links = await Link.find({ code: { $in: groups.map((g) => g._id) } }).lean();
  const byCode = new Map(links.map((l) => [l.code, l]));
  res.json(groups.filter((g) => byCode.has(g._id)).map((g) =>
    adminRow(byCode.get(g._id), { reports: g.count, lastReport: g.last, reasons: g.reasons.filter(Boolean).slice(0, 5) })));
}));

app.get("/api/admin/links", requireAdmin, wrap(async (req, res) => {
  const q = String(req.query.q || "").trim().slice(0, 100);
  const filter = q ? { $or: [{ code: { $regex: escapeRe(q), $options: "i" } }, { url: { $regex: escapeRe(q), $options: "i" } }] } : {};
  const links = await Link.find(filter).sort({ createdAt: -1 }).limit(50).lean();
  res.json(links.map((l) => adminRow(l)));
}));

app.post("/api/admin/links/:code/:action", requireAdmin, wrap(async (req, res) => {
  const { code, action } = req.params;
  const link = await Link.findOne({ code });
  if (!link) return res.status(404).json({ error: "Lien introuvable." });
  if (action === "disable") { link.disabled = true; await link.save(); }
  else if (action === "enable") { link.disabled = false; await link.save(); await Report.deleteMany({ code }); }
  else if (action === "dismiss") { await Report.deleteMany({ code }); }
  else return res.status(400).json({ error: "Action inconnue." });
  res.json({ ok: true });
}));

app.delete("/api/admin/links/:code", requireAdmin, wrap(async (req, res) => {
  const link = await Link.findOneAndDelete({ code: req.params.code });
  if (!link) return res.status(404).json({ error: "Lien introuvable." });
  await Promise.all([Click.deleteMany({ code: link.code }), Report.deleteMany({ code: link.code })]);
  res.json({ ok: true });
}));

/* ---------- Pages ---------- */
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));
app.get("/stats/:code", (req, res) => res.sendFile(path.join(__dirname, "public", "stats.html")));
app.get("/p/:code", (req, res) => res.sendFile(path.join(__dirname, "public", "preview.html")));

app.get("/:code", wrap(async (req, res) => {
  const link = await Link.findOne({ code: req.params.code }).lean();
  const gone = !link || link.disabled || (link.expiresAt && link.expiresAt < new Date());
  if (gone) return res.status(link ? 410 : 404).sendFile(path.join(__dirname, "public", "404.html"));

  const ua = req.get("user-agent") || "";
  if (!BOT_RE.test(ua)) {
    Click.create({
      code: link.code, visitor: sha(SALT + req.ip + ua), referrer: referrerHost(req), ...parseUA(ua),
      country: (req.get("cf-ipcountry") || req.get("x-vercel-ip-country") || "Inconnu").toUpperCase(),
    }).catch(() => {});
    Link.updateOne({ _id: link._id }, { $inc: { clicks: 1 } }).catch(() => {});
  }
  res.set("Cache-Control", "no-store");
  res.redirect(302, link.url);
}));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Erreur serveur." });
});

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => app.listen(PORT, () => console.log(`http://localhost:${PORT}`)))
  .catch((err) => { console.error("MongoDB :", err.message); process.exit(1); });
