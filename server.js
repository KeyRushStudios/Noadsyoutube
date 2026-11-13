const express = require("express"), multer = require("multer"), crypto = require("crypto"), fs = require("fs"), path = require("path");
const app = express(), DATA = process.env.DATA_DIR || "./data";
fs.mkdirSync(DATA + "/uploads", { recursive: true });
const F = DATA + "/db.json";
let db = { users: {}, videos: [], subs: {}, lives: {}, pending: {}, tokens: {} };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(F))); } catch (e) {}
const save = () => fs.writeFileSync(F, JSON.stringify(db));
const rid = n => crypto.randomBytes(n).toString("hex");
const hash = (p, s) => crypto.scryptSync(p, s, 32).toString("hex");
const chan = e => ({ id: db.users[e].id, name: db.users[e].name });

app.use(express.json());
app.use("/uploads", express.static(DATA + "/uploads"));
app.use(express.static("public"));
const up = multer({
  storage: multer.diskStorage({ destination: DATA + "/uploads", filename: (r, f, cb) => cb(null, rid(8) + path.extname(f.originalname).toLowerCase()) }),
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (r, f, cb) => cb(null, /^video\//.test(f.mimetype))
});
const auth = (req, res, next) => {
  const e = db.tokens[(req.headers.authorization || "").slice(7)];
  if (!e) return res.status(401).json({ error: "Bitte anmelden" });
  req.email = e; next();
};

// Anmeldung: E-Mail + Passwort, dann 16-stelliger Code per Resend
app.post("/api/code", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase(), pw = String(req.body.password || "");
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Ungültige E-Mail" });
  if (pw.length < 8 || pw.length > 47) return res.status(400).json({ error: "Passwort: 8 bis 47 Zeichen" });
  const u = db.users[email];
  if (u && hash(pw, u.salt) !== u.hash) return res.status(401).json({ error: "Falsches Passwort" });
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", b = crypto.randomBytes(16);
  const code = [...b].map(x => A[x % A.length]).join("");
  const salt = u ? u.salt : rid(8);
  db.pending[email] = { code, salt, hash: hash(pw, salt), exp: Date.now() + 10 * 60000, tries: 0 };
  save();
  try {
    const r = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": process.env.BREVO_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ sender: { name: "Flux", email: process.env.MAIL_FROM }, to: [{ email }], subject: "Dein Flux-Code", textContent: "Dein Code: " + code + "\nGültig für 10 Minuten." })
    });
    if (!r.ok) throw new Error(await r.text());
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: "E-Mail konnte nicht gesendet werden" }); }
});
app.post("/api/verify", (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase(), p = db.pending[email];
  if (!p || p.exp < Date.now() || p.tries >= 5) return res.status(400).json({ error: "Code abgelaufen. Bitte neu anfordern." });
  p.tries++;
  if (String(req.body.code || "").trim().toUpperCase() !== p.code) { save(); return res.status(400).json({ error: "Code falsch" }); }
  if (!db.users[email]) db.users[email] = { id: rid(6), name: email.split("@")[0], salt: p.salt, hash: p.hash };
  delete db.pending[email];
  const token = rid(24); db.tokens[token] = email; save();
  res.json({ token, channel: chan(email) });
});
app.get("/api/me", auth, (req, res) => res.json({ channel: chan(req.email), subs: db.subs[req.email] || [] }));

// Videos: ansehen ohne Konto, hochladen nur mit Konto
app.get("/api/videos", (req, res) => res.json(db.videos.slice().reverse().map(v => ({ id: v.id, title: v.title, file: v.file, views: v.views, t: v.t, channel: chan(v.owner) }))));
app.post("/api/videos", auth, up.single("video"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Bitte eine Videodatei wählen" });
  const v = { id: rid(5), title: String(req.body.title || "Ohne Titel").slice(0, 100), file: "/uploads/" + req.file.filename, owner: req.email, views: 0, t: Date.now() };
  db.videos.push(v); save(); res.json({ ok: true });
});
app.post("/api/videos/:id/view", (req, res) => { const v = db.videos.find(x => x.id === req.params.id); if (v) { v.views++; save(); } res.json({ ok: true }); });
app.post("/api/sub/:cid", auth, (req, res) => {
  const s = db.subs[req.email] = db.subs[req.email] || [], i = s.indexOf(req.params.cid);
  i > -1 ? s.splice(i, 1) : s.push(req.params.cid); save(); res.json({ subs: s });
});

// Live: jeder angemeldete Nutzer, keine Mindestanzahl an Abos. Übertragung über Cloudflare Stream (WebRTC/WHIP)
const CF = "https://api.cloudflare.com/client/v4/accounts/" + process.env.CF_ACCOUNT_ID + "/stream/live_inputs";
const cfh = { Authorization: "Bearer " + process.env.CF_API_TOKEN, "Content-Type": "application/json" };
app.post("/api/live", auth, async (req, res) => {
  try {
    const r = await (await fetch(CF, { method: "POST", headers: cfh, body: JSON.stringify({ meta: { name: String(req.body.title || "Live").slice(0, 100) }, recording: { mode: "automatic" } }) })).json();
    if (!r.success) throw new Error(JSON.stringify(r.errors));
    const id = rid(5);
    db.lives[id] = { id, title: String(req.body.title || "Live").slice(0, 100), owner: req.email, uid: r.result.uid, ping: Date.now() };
    save(); res.json({ id, whip: r.result.webRTC.url });
  } catch (e) { console.error(e.message); res.status(500).json({ error: "Live konnte nicht gestartet werden" }); }
});
app.post("/api/live/:id/ping", auth, (req, res) => { const l = db.lives[req.params.id]; if (l && l.owner === req.email) l.ping = Date.now(); res.json({ ok: true }); });
app.delete("/api/live/:id", auth, async (req, res) => {
  const l = db.lives[req.params.id];
  if (l && l.owner === req.email) { delete db.lives[l.id]; save(); fetch(CF + "/" + l.uid, { method: "DELETE", headers: cfh }).catch(() => {}); }
  res.json({ ok: true });
});
app.get("/api/lives", (req, res) => res.json(Object.values(db.lives).filter(l => Date.now() - l.ping < 45000).map(l => ({ id: l.id, title: l.title, uid: l.uid, channel: chan(l.owner) }))));

app.listen(process.env.PORT || 3000, () => console.log("Flux läuft"));
