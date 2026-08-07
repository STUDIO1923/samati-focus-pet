import crypto from "node:crypto";
import express from "express";
import pg from "pg";

const { Pool } = pg;
const app = express();
const port = Number(process.env.PORT || 3000);
const clientId = process.env.GOOGLE_CLIENT_ID || "";
const secret = process.env.SESSION_SECRET || "dev-only-change-me";
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL?.includes("localhost") ? false : { rejectUnauthorized: false } });

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(express.static("public", { extensions: ["html"] }));

const b64 = value => Buffer.from(value).toString("base64url");
function signSession(user) {
  const body = b64(JSON.stringify({ sub: user.sub, email: user.email, name: user.name, picture: user.picture, exp: Date.now() + 30 * 864e5 }));
  const sig = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${sig}`;
}
function readSession(req) {
  const raw = (req.headers.cookie || "").split(";").map(v => v.trim()).find(v => v.startsWith("samati_session="))?.slice(15);
  if (!raw) return null;
  const [body, sig] = raw.split(".");
  const expected = crypto.createHmac("sha256", secret).update(body || "").digest("base64url");
  if (!sig || sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try { const user = JSON.parse(Buffer.from(body, "base64url")); return user.exp > Date.now() ? user : null; } catch { return null; }
}
function requireUser(req, res, next) {
  req.user = readSession(req);
  if (!req.user) return res.status(401).json({ error: "unauthorized" });
  next();
}

app.get("/api/config", (_req, res) => res.json({ googleClientId: clientId }));
app.get("/api/me", (req, res) => res.json({ user: readSession(req) }));
app.post("/api/auth/google", async (req, res) => {
  if (!clientId) return res.status(503).json({ error: "Google Sign-In is not configured" });
  try {
    const { OAuth2Client } = await import("google-auth-library");
    const ticket = await new OAuth2Client(clientId).verifyIdToken({ idToken: req.body.credential, audience: clientId });
    const p = ticket.getPayload();
    if (!p?.sub || !p.email_verified) return res.status(401).json({ error: "invalid Google account" });
    const user = { sub: p.sub, email: p.email, name: p.name || p.email, picture: p.picture || "" };
    res.cookie("samati_session", signSession(user), { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", maxAge: 30 * 864e5, path: "/" });
    res.json({ user });
  } catch { res.status(401).json({ error: "invalid Google token" }); }
});
app.post("/api/logout", (_req, res) => { res.clearCookie("samati_session", { path: "/" }); res.json({ ok: true }); });
app.get("/api/save", requireUser, async (req, res) => {
  const result = await pool.query("SELECT state, updated_at FROM game_saves WHERE google_sub = $1", [req.user.sub]);
  res.json(result.rows[0] || { state: null });
});
app.put("/api/save", requireUser, async (req, res) => {
  const state = req.body?.state;
  if (!state?.pet || !state?.player) return res.status(400).json({ error: "invalid save" });
  await pool.query(`INSERT INTO game_saves (google_sub, email, state, updated_at) VALUES ($1,$2,$3,NOW())
    ON CONFLICT (google_sub) DO UPDATE SET email=EXCLUDED.email, state=EXCLUDED.state, updated_at=NOW()`, [req.user.sub, req.user.email, state]);
  res.json({ ok: true });
});
app.get("/api/friends/:code", requireUser, async (req, res) => {
  const code = String(req.params.code || "").toUpperCase();
  const result = await pool.query(`SELECT state FROM game_saves
    WHERE UPPER(state->'account'->>'code') = $1 LIMIT 1`, [code]);
  const state = result.rows[0]?.state;
  if (!state) return res.status(404).json({ error: "friend not found" });
  res.json({ friend: {
    code, name: state.player?.name || "เพื่อน",
    petName: state.pet?.name || "Mori", petForm: state.pet?.form || "seed"
  }});
});
app.put("/api/rooms/:code/presence", requireUser, async (req, res) => {
  const code = String(req.params.code || "").toUpperCase();
  if (!/^[A-Z0-9]{4,10}$/.test(code)) return res.status(400).json({ error: "invalid room" });
  const profile = req.body?.profile || {};
  await pool.query(`INSERT INTO room_presence (room_code, google_sub, profile, seen_at)
    VALUES ($1,$2,$3,NOW()) ON CONFLICT (room_code,google_sub)
    DO UPDATE SET profile=EXCLUDED.profile, seen_at=NOW()`, [code, req.user.sub, profile]);
  await pool.query("DELETE FROM room_presence WHERE seen_at < NOW() - INTERVAL '20 seconds'");
  const members = await pool.query("SELECT profile FROM room_presence WHERE room_code=$1 ORDER BY seen_at DESC LIMIT 5", [code]);
  res.json({ members: members.rows.map(r => r.profile) });
});
app.get("/api/rooms/:code/presence", requireUser, async (req, res) => {
  const code = String(req.params.code || "").toUpperCase();
  if (!/^[A-Z0-9]{4,10}$/.test(code)) return res.status(400).json({ error: "invalid room" });
  await pool.query("DELETE FROM room_presence WHERE seen_at < NOW() - INTERVAL '20 seconds'");
  const members = await pool.query("SELECT profile FROM room_presence WHERE room_code=$1 ORDER BY seen_at DESC LIMIT 5", [code]);
  res.json({ members: members.rows.map(r => r.profile) });
});
app.delete("/api/rooms/:code/presence", requireUser, async (req, res) => {
  await pool.query("DELETE FROM room_presence WHERE room_code=$1 AND google_sub=$2", [String(req.params.code || "").toUpperCase(), req.user.sub]);
  res.json({ ok: true });
});
app.get("/api/health", (_req, res) => res.json({ ok: true }));

await pool.query(`CREATE TABLE IF NOT EXISTS game_saves (
  google_sub TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  state JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`);
await pool.query(`CREATE TABLE IF NOT EXISTS room_presence (
  room_code TEXT NOT NULL,
  google_sub TEXT NOT NULL,
  profile JSONB NOT NULL,
  seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (room_code, google_sub)
)`);
app.listen(port, "0.0.0.0", () => console.log(`SAMATI listening on ${port}`));
