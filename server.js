import crypto from "node:crypto";
import express from "express";
import pg from "pg";

const { Pool } = pg;
const app = express();
const port = Number(process.env.PORT || 3000);
const clientId = process.env.GOOGLE_CLIENT_ID || "";
const secret = process.env.SESSION_SECRET || "dev-only-change-me";
if (process.env.NODE_ENV === "production" && secret === "dev-only-change-me") {
  throw new Error("SESSION_SECRET must be configured in production");
}
// The project owner must retain server-side admin access even if Render's
// optional ADMIN_EMAILS environment variable is removed during a redeploy.
const ownerAdminEmails = ["jenwzch@gmail.com"];
const adminEmails = new Set([
  ...ownerAdminEmails,
  ...String(process.env.ADMIN_EMAILS || "").split(",")
].map(v => v.trim().toLowerCase()).filter(Boolean));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL?.includes("localhost") ? false : { rejectUnauthorized: false } });

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    const origin = req.get("origin");
    if (origin && origin !== `${req.protocol}://${req.get("host")}`) return res.status(403).json({ error: "invalid origin" });
  }
  next();
});

const rateBuckets = new Map();
function rateLimit(name, limit, windowMs = 60_000) {
  return (req, res, next) => {
    const user = readSession(req);
    const key = `${name}:${user?.sub || req.ip}`;
    const t = Date.now();
    let bucket = rateBuckets.get(key);
    if (!bucket || bucket.resetAt <= t) bucket = { count: 0, resetAt: t + windowMs };
    bucket.count += 1; rateBuckets.set(key, bucket);
    res.setHeader("RateLimit-Limit", String(limit));
    res.setHeader("RateLimit-Remaining", String(Math.max(0, limit - bucket.count)));
    if (bucket.count > limit) return res.status(429).json({ error: "too many requests" });
    next();
  };
}
app.use("/api", rateLimit("api", 180));
app.use(express.static("public", { extensions: ["html"] }));

const b64 = value => Buffer.from(value).toString("base64url");
function signSession(user) {
  const body = b64(JSON.stringify({ sub: user.sub, email: user.email, name: user.name, picture: user.picture, sid:user.sid, exp: Date.now() + 30 * 864e5 }));
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
function getClientIp(req) {
  const raw = String(req.ip || req.socket?.remoteAddress || "").trim();
  return raw.replace(/^::ffff:/, "").replace(/^\[|\]$/g, "").slice(0, 64);
}
async function requireUser(req, res, next) {
  req.user = readSession(req);
  if (!req.user) return res.status(401).json({ error: "unauthorized" });
  req.clientIp = getClientIp(req);
  try {
    const active = await pool.query("SELECT session_id FROM active_sessions WHERE google_sub=$1", [req.user.sub]);
    if (!req.user.sid || active.rows[0]?.session_id !== req.user.sid) return res.status(401).json({ error: "session replaced" });
    if (!adminEmails.has(String(req.user.email || "").toLowerCase())) {
      const blocked = await pool.query("SELECT 1 FROM ip_blocks WHERE ip=$1", [req.clientIp]);
      if (blocked.rows[0]) return res.status(403).json({ error: "ip blocked" });
    }
    await pool.query(`INSERT INTO account_activity (google_sub,email,last_ip,last_seen)
      VALUES ($1,$2,$3,NOW()) ON CONFLICT (google_sub) DO UPDATE
      SET email=EXCLUDED.email,last_ip=EXCLUDED.last_ip,last_seen=NOW()`,
      [req.user.sub, req.user.email, req.clientIp]);
    next();
  } catch (error) { next(error); }
}
async function requireAdmin(req, res, next) {
  req.user = readSession(req);
  if (!req.user) return res.status(401).json({ error: "unauthorized" });
  try {
    const active=await pool.query("SELECT session_id FROM active_sessions WHERE google_sub=$1",[req.user.sub]);
    if(!req.user.sid||active.rows[0]?.session_id!==req.user.sid)return res.status(401).json({error:"session replaced"});
    if (!adminEmails.has(String(req.user.email || "").toLowerCase())) return res.status(403).json({ error: "admin only" });
    next();
  } catch(error){next(error);}
}

const num = (value, fallback = 0) => Number.isFinite(Number(value)) ? Number(value) : fallback;
const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
function publicUser(user) {
  const { sid: _sid, ...safe } = user;
  return { ...safe, admin: adminEmails.has(String(user.email || "").toLowerCase()) };
}
const collectibleAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function collectibleId() { const bytes=crypto.randomBytes(13); return Array.from(bytes,b=>collectibleAlphabet[b%collectibleAlphabet.length]).join(""); }
function cleanPlaced(list){return Array.isArray(list)?list.slice(0,30).map(p=>({id:String(p?.id||"").slice(0,40),x:clamp(num(p?.x,108),-50,270),y:clamp(num(p?.y,100),-50,240),on:p?.on!==false})).filter(p=>p.id):[];}
function cleanHouse(raw,state){const p=raw?.place||state?.place||{};return{code:String(state?.account?.code||"").slice(0,10).toUpperCase(),name:String(state?.player?.name||"Player").slice(0,24),player:state?.player||{},pet:state?.pet||{},place:{home:cleanPlaced(p.home),yard:cleanPlaced(p.yard),garden:cleanPlaced(p.garden)},vip:state?.vip||{}};}
async function recordSecurityEvent(user, kind, severity, details) {
  await pool.query(`INSERT INTO security_events (google_sub, email, kind, severity, details)
    VALUES ($1,$2,$3,$4,$5)`, [user.sub, user.email, kind, severity, details || {}]);
}
function normalizeEconomyState(incoming, previous, elapsedMinutes) {
  const state = structuredClone(incoming);
  const oldCoins = previous ? clamp(Math.round(num(previous.coins, 120)), 0, 9_999_999) : 120;
  const claimed = clamp(Math.round(num(state.coins, oldCoins)), 0, 9_999_999);
  const maxEarn = previous ? Math.max(40, Math.floor(elapsedMinutes * 24 + 40)) : 0;
  const suspicious = previous ? claimed > oldCoins + maxEarn : claimed > 120;
  state.coins = suspicious ? oldCoins : claimed;

  if (state.pet) {
    state.pet.lv = clamp(Math.round(num(state.pet.lv, 1)), 1, 100);
    state.pet.xp = clamp(Math.round(num(state.pet.xp, 0)), 0, 10_000_000);
  }
  if (state.stats) {
    const oldFocus = num(previous?.stats?.focusMin, 0);
    const claimedFocus = Math.max(0, num(state.stats.focusMin, oldFocus));
    if (previous && claimedFocus > oldFocus + elapsedMinutes + 3) state.stats.focusMin = oldFocus;
  }
  return { state, suspicious, claimedCoins: claimed, trustedCoins: oldCoins, maxEarn };
}

app.get("/api/config", (_req, res) => res.json({ googleClientId: clientId }));
app.get("/api/me", async (req, res) => {const user=readSession(req);if(!user)return res.json({user:null});const active=await pool.query("SELECT session_id FROM active_sessions WHERE google_sub=$1",[user.sub]);if(!user.sid||active.rows[0]?.session_id!==user.sid)return res.status(401).json({error:"session replaced"});res.json({user:publicUser(user)});});
app.post("/api/auth/google", async (req, res) => {
  if (!clientId) return res.status(503).json({ error: "Google Sign-In is not configured" });
  try {
    const { OAuth2Client } = await import("google-auth-library");
    const ticket = await new OAuth2Client(clientId).verifyIdToken({ idToken: req.body.credential, audience: clientId });
    const p = ticket.getPayload();
    if (!p?.sub || !p.email_verified) return res.status(401).json({ error: "invalid Google account" });
    const user = { sub: p.sub, email: p.email, name: p.name || p.email, picture: p.picture || "", sid:crypto.randomUUID() };
    const ip = getClientIp(req);
    if (!adminEmails.has(String(user.email || "").toLowerCase())) {
      const blocked = await pool.query("SELECT 1 FROM ip_blocks WHERE ip=$1", [ip]);
      if (blocked.rows[0]) return res.status(403).json({ error: "ip blocked" });
    }
    await pool.query(`INSERT INTO account_activity (google_sub,email,last_ip,last_seen)
      VALUES ($1,$2,$3,NOW()) ON CONFLICT (google_sub) DO UPDATE
      SET email=EXCLUDED.email,last_ip=EXCLUDED.last_ip,last_seen=NOW()`, [user.sub, user.email, ip]);
    await pool.query(`INSERT INTO active_sessions (google_sub,session_id,updated_at) VALUES ($1,$2,NOW())
      ON CONFLICT (google_sub) DO UPDATE SET session_id=EXCLUDED.session_id,updated_at=NOW()`, [user.sub,user.sid]);
    res.cookie("samati_session", signSession(user), { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", maxAge: 30 * 864e5, path: "/" });
    res.json({ user: publicUser(user) });
  } catch { res.status(401).json({ error: "invalid Google token" }); }
});
app.post("/api/logout", async (req, res) => { const u=readSession(req);if(u?.sid)await pool.query("DELETE FROM active_sessions WHERE google_sub=$1 AND session_id=$2",[u.sub,u.sid]);res.clearCookie("samati_session", { path: "/" }); res.json({ ok: true }); });
app.get("/api/save", requireUser, async (req, res) => {
  const result = await pool.query("SELECT state, updated_at FROM game_saves WHERE google_sub = $1", [req.user.sub]);
  res.json(result.rows[0] || { state: null });
});
app.post("/api/collectibles/id", rateLimit("collectible-id",30), requireUser, async(req,res)=>{
  const kind=String(req.body?.kind||"item").replace(/[^a-z0-9_-]/gi,"").slice(0,24)||"item",ref=String(req.body?.ref||crypto.randomUUID()).slice(0,120);
  const old=await pool.query("SELECT id FROM collectible_ids WHERE google_sub=$1 AND kind=$2 AND ref=$3",[req.user.sub,kind,ref]);if(old.rows[0])return res.json({id:old.rows[0].id});
  for(let n=0;n<8;n++)try{const proposed=String(req.body?.id||"").toUpperCase(),id=n===0&&/^[A-Z0-9]{13}$/.test(proposed)?proposed:collectibleId();await pool.query("INSERT INTO collectible_ids(id,google_sub,kind,ref) VALUES($1,$2,$3,$4)",[id,req.user.sub,kind,ref]);return res.json({id});}catch(e){if(e.code!=="23505")throw e;}
  res.status(503).json({error:"could not issue collectible id"});
});
app.delete("/api/save", rateLimit("delete-save", 3), requireUser, async (req, res) => {
  await pool.query("DELETE FROM game_saves WHERE google_sub=$1", [req.user.sub]);
  await pool.query("DELETE FROM room_presence WHERE google_sub=$1", [req.user.sub]).catch(()=>{});
  await pool.query("DELETE FROM plaza_presence WHERE google_sub=$1", [req.user.sub]).catch(()=>{});
  res.json({ ok: true });
});
app.post("/api/focus/start", rateLimit("focus-start", 8), requireUser, async (req, res) => {
  const minutes = clamp(Math.round(num(req.body?.minutes, 0)), 5, 120);
  const difficulty = ["easy", "mid", "hard"].includes(req.body?.difficulty) ? req.body.difficulty : "mid";
  const mode = ["home", "garden", "wild", "heal"].includes(req.body?.mode) ? req.body.mode : "home";
  const token = crypto.randomUUID();
  await pool.query(`INSERT INTO focus_sessions (token,google_sub,planned_minutes,difficulty,mode,started_at,completed_at)
    VALUES ($1,$2,$3,$4,$5,NOW(),NULL)`, [token, req.user.sub, minutes, difficulty, mode]);
  res.json({ token, startedAt: Date.now(), minutes });
});
app.post("/api/focus/complete", rateLimit("focus-complete", 12), requireUser, async (req, res) => {
  const token = String(req.body?.token || "");
  const db = await pool.connect();
  try {
    await db.query("BEGIN");
    await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [req.user.sub]);
    const found = await db.query(`SELECT * FROM focus_sessions
      WHERE token=$1 AND google_sub=$2 FOR UPDATE`, [token, req.user.sub]);
    const session = found.rows[0];
    if (!session || session.completed_at) {
      await db.query("ROLLBACK");
      return res.status(409).json({ error: "focus session already used or invalid" });
    }
    const elapsed = clamp((Date.now() - new Date(session.started_at).getTime()) / 60000, 0, Number(session.planned_minutes));
    const complete = Boolean(req.body?.complete) && elapsed >= Number(session.planned_minutes) - 0.15;
    const creditedMinutes = complete ? Number(session.planned_minutes) : elapsed;
    const diff = { easy: 1, mid: 1.3, hard: 1.6 }[session.difficulty] || 1.3;
    const modeRate = session.mode === "heal" ? 0 : session.mode === "wild" ? 1.2 : 1;
    const coins = Math.max(0, Math.round(creditedMinutes * 0.7 * diff * modeRate * (complete ? 1 : 0.5)));
    const save = await db.query("SELECT state FROM game_saves WHERE google_sub=$1 FOR UPDATE", [req.user.sub]);
    if (!save.rows[0]) {
      await db.query("ROLLBACK");
      return res.status(409).json({ error: "save must exist before focus rewards" });
    }
    const state = save.rows[0].state;
    state.coins = clamp(Math.round(num(state.coins, 120)) + coins, 0, 9_999_999);
    await db.query("UPDATE game_saves SET state=$2,updated_at=NOW() WHERE google_sub=$1", [req.user.sub, state]);
    await db.query("UPDATE focus_sessions SET completed_at=NOW(),credited_minutes=$2,coins_awarded=$3 WHERE token=$1", [token, creditedMinutes, coins]);
    await db.query(`INSERT INTO economy_events (google_sub,kind,amount,reference,details)
      VALUES ($1,'focus_reward',$2,$3,$4)`, [req.user.sub, coins, token, { creditedMinutes, complete, mode: session.mode }]);
    await db.query("COMMIT");
    res.json({ ok: true, coins: state.coins, awarded: coins, creditedMinutes, complete });
  } catch (error) {
    await db.query("ROLLBACK").catch(() => {}); throw error;
  } finally { db.release(); }
});
app.put("/api/save", rateLimit("save", 20), requireUser, async (req, res) => {
  const state = req.body?.state;
  if (!state?.pet || !state?.player) return res.status(400).json({ error: "invalid save" });
  const db = await pool.connect();
  try {
    await db.query("BEGIN");
    await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [req.user.sub]);
    const prior = await db.query("SELECT state, updated_at FROM game_saves WHERE google_sub=$1 FOR UPDATE", [req.user.sub]);
    const previous = prior.rows[0]?.state || null;
    const elapsedMinutes = prior.rows[0] ? Math.max(0, (Date.now() - new Date(prior.rows[0].updated_at).getTime()) / 60000) : 0;
    const adminSave = adminEmails.has(String(req.user.email || "").toLowerCase());
    const checked = adminSave
      ? { state: structuredClone(state), suspicious: false, claimedCoins: num(state.coins), trustedCoins: num(previous?.coins), maxEarn: 0 }
      : normalizeEconomyState(state, previous, elapsedMinutes);
    if (checked.suspicious) await db.query(`INSERT INTO security_events (google_sub,email,kind,severity,details)
      VALUES ($1,$2,'coin_inflation',8,$3)`, [req.user.sub, req.user.email, {
      claimed: checked.claimedCoins, trusted: checked.trustedCoins, allowedIncrease: checked.maxEarn
    }]);
    await db.query(`INSERT INTO game_saves (google_sub, email, state, updated_at) VALUES ($1,$2,$3,NOW())
      ON CONFLICT (google_sub) DO UPDATE SET email=EXCLUDED.email, state=EXCLUDED.state, updated_at=NOW()`, [req.user.sub, req.user.email, checked.state]);
    await db.query("COMMIT");
    res.json({ ok: true, state: checked.state, security: { adjusted: checked.suspicious } });
  } catch (error) {
    await db.query("ROLLBACK").catch(() => {});
    throw error;
  } finally { db.release(); }
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
app.get("/api/friends", rateLimit("friend-search", 30), requireUser, async (req, res) => {
  const name = String(req.query.name || "").trim().replace(/[%_]/g, "").slice(0, 24);
  if (name.length < 2) return res.status(400).json({ error: "name too short" });
  const result = await pool.query(`SELECT state FROM game_saves
    WHERE state->'player'->>'name' ILIKE $1 ORDER BY updated_at DESC LIMIT 10`, [`%${name}%`]);
  res.json({ friends: result.rows.map(({ state }) => ({
    code: String(state.account?.code || "").toUpperCase(), name: state.player?.name || "ผู้เล่น",
    petName: state.pet?.name || "Mori", petForm: state.pet?.form || "seed", petLv: clamp(Math.round(num(state.pet?.lv, 1)), 1, 100)
  })).filter(v => v.code) });
});
app.post("/api/friends/:code/cheer", rateLimit("friend-cheer", 20), requireUser, async (req, res) => {
  const code=String(req.params.code||"").toUpperCase();
  const sender=await pool.query("SELECT state FROM game_saves WHERE google_sub=$1",[req.user.sub]);
  const senderCode=String(sender.rows[0]?.state?.account?.code||"").toUpperCase();
  if(!senderCode||senderCode===code)return res.status(400).json({error:"invalid friend"});
  const db=await pool.connect();
  try{
    await db.query("BEGIN");
    const target=await db.query("SELECT google_sub,state FROM game_saves WHERE UPPER(state->'account'->>'code')=$1 FOR UPDATE",[code]);
    if(!target.rows[0]){await db.query("ROLLBACK");return res.status(404).json({error:"friend not found"});}
    const ins=await db.query(`INSERT INTO friend_cheers(sender_sub,target_sub,sent_on) VALUES($1,$2,(NOW() AT TIME ZONE 'Asia/Bangkok')::date) ON CONFLICT DO NOTHING RETURNING sender_sub`,[req.user.sub,target.rows[0].google_sub]);
    if(!ins.rowCount){await db.query("ROLLBACK");return res.status(409).json({error:"already cheered today"});}
    const state=target.rows[0].state;state.cheers=clamp(Math.round(num(state.cheers,0))+1,0,999999);
    await db.query("UPDATE game_saves SET state=$2,updated_at=NOW() WHERE google_sub=$1",[target.rows[0].google_sub,state]);
    await db.query("COMMIT");res.json({ok:true,cheers:state.cheers});
  }catch(error){await db.query("ROLLBACK").catch(()=>{});throw error;}finally{db.release();}
});
app.get("/api/admin/security", rateLimit("admin-security", 30), requireAdmin, async (_req, res) => {
  const [events, counts] = await Promise.all([
    pool.query(`SELECT email,kind,severity,details,created_at FROM security_events
      ORDER BY created_at DESC LIMIT 100`),
    pool.query(`SELECT kind,COUNT(*)::int AS count FROM security_events
      WHERE created_at > NOW()-INTERVAL '24 hours' GROUP BY kind ORDER BY count DESC`)
  ]);
  res.json({ events: events.rows, counts: counts.rows });
});
app.get("/api/admin/players", rateLimit("admin-players", 30), requireAdmin, async (_req, res) => {
  const result = await pool.query(`SELECT g.google_sub,g.email,g.state,g.updated_at,
      a.last_ip,a.last_seen,EXISTS(SELECT 1 FROM ip_blocks b WHERE b.ip=a.last_ip) AS ip_blocked
    FROM game_saves g LEFT JOIN account_activity a ON a.google_sub=g.google_sub
    ORDER BY COALESCE(a.last_seen,g.updated_at) DESC LIMIT 500`);
  res.json({ players: result.rows.map(r => ({
    sub: r.google_sub, email: r.email, state: r.state, ip: r.last_ip || "ไม่ทราบ",
    lastSeen: r.last_seen || r.updated_at, online: Date.now()-new Date(r.last_seen || r.updated_at).getTime()<120000,
    ipBlocked: Boolean(r.ip_blocked)
  })) });
});
app.post("/api/admin/players/:sub/grant", rateLimit("admin-grant", 60), requireAdmin, async (req, res) => {
  const field = req.body?.field === "crystal" ? "crystal" : req.body?.field === "coins" ? "coins" : "";
  const amount = clamp(Math.round(num(req.body?.amount)), -1_000_000, 1_000_000);
  if (!field || !amount) return res.status(400).json({ error: "invalid grant" });
  const found = await pool.query("SELECT state FROM game_saves WHERE google_sub=$1", [req.params.sub]);
  if (!found.rows[0]) return res.status(404).json({ error: "account not found" });
  const state = found.rows[0].state;
  state[field] = clamp(Math.round(num(state[field])) + amount, 0, 9_999_999);
  await pool.query("UPDATE game_saves SET state=$2,updated_at=NOW() WHERE google_sub=$1", [req.params.sub, state]);
  await pool.query(`INSERT INTO economy_events (google_sub,kind,amount,reference,details)
    VALUES ($1,'admin_grant',$2,$3,$4)`, [req.params.sub, amount, crypto.randomUUID(), { field, by: req.user.email }]);
  res.json({ ok: true, value: state[field] });
});
app.post("/api/admin/ip-blocks", rateLimit("admin-ip", 30), requireAdmin, async (req, res) => {
  const ip = String(req.body?.ip || "").trim().replace(/^::ffff:/, "").slice(0,64);
  if (!ip || ip === "ไม่ทราบ") return res.status(400).json({ error: "invalid ip" });
  await pool.query(`INSERT INTO ip_blocks (ip,reason,created_by) VALUES ($1,$2,$3)
    ON CONFLICT (ip) DO UPDATE SET reason=EXCLUDED.reason,created_by=EXCLUDED.created_by,created_at=NOW()`,
    [ip, String(req.body?.reason || "บล็อกโดยผู้ดูแล").slice(0,200), req.user.email]);
  res.json({ ok:true });
});
app.delete("/api/admin/ip-blocks/:ip", rateLimit("admin-ip", 30), requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM ip_blocks WHERE ip=$1", [String(req.params.ip).replace(/^::ffff:/, "")]);
  res.json({ ok:true });
});
app.delete("/api/admin/players/:sub", rateLimit("admin-delete", 20), requireAdmin, async (req, res) => {
  const target = await pool.query("SELECT email FROM game_saves WHERE google_sub=$1", [req.params.sub]);
  if (!target.rows[0]) return res.status(404).json({ error: "account not found" });
  if (adminEmails.has(String(target.rows[0].email || "").toLowerCase())) return res.status(403).json({ error: "cannot delete admin" });
  const db=await pool.connect();
  try {
    await db.query("BEGIN");
    await db.query("DELETE FROM room_presence WHERE google_sub=$1", [req.params.sub]);
    await db.query("DELETE FROM plaza_presence WHERE google_sub=$1", [req.params.sub]);
    await db.query("DELETE FROM game_saves WHERE google_sub=$1", [req.params.sub]);
    await db.query("DELETE FROM account_activity WHERE google_sub=$1", [req.params.sub]);
    await db.query("COMMIT");
    res.json({ ok:true });
  } catch(error){ await db.query("ROLLBACK").catch(()=>{}); throw error; }
  finally { db.release(); }
});
async function roomState(code, after = 0) {
  await pool.query("DELETE FROM room_presence WHERE seen_at < NOW() - INTERVAL '20 seconds'");
  const [members, owner, messages] = await Promise.all([
    pool.query("SELECT profile FROM room_presence WHERE room_code=$1 ORDER BY seen_at DESC LIMIT 5", [code]),
    pool.query("SELECT state FROM game_saves WHERE UPPER(state->'account'->>'code')=$1 LIMIT 1", [code]),
    pool.query("SELECT id,name,message,created_at FROM room_messages WHERE room_code=$1 AND id>$2 ORDER BY id DESC LIMIT 50", [code, Math.max(0, Number(after) || 0)])
  ]);
  const s = owner.rows[0]?.state;
  const liveHouse=members.rows.map(r=>r.profile).find(p=>p?.code===code)?.house;
  const house = liveHouse || (s ? { code, name: s.player?.name || "ผู้เล่น", player: s.player || {}, pet: s.pet || {}, place: {
    home:Array.isArray(s.place?.home)?s.place.home.slice(0,30):[],yard:Array.isArray(s.place?.yard)?s.place.yard.slice(0,30):[],garden:Array.isArray(s.place?.garden)?s.place.garden.slice(0,30):[]
  }, vip: s.vip || {} } : null);
  return { members: members.rows.map(r => r.profile), house, messages: messages.rows.reverse(), capacity: 5 };
}
app.put("/api/rooms/:code/presence", rateLimit("presence", 40), requireUser, async (req, res) => {
  const code = String(req.params.code || "").toUpperCase();
  if (!/^[A-Z0-9]{4,10}$/.test(code)) return res.status(400).json({ error: "invalid room" });
  const trusted = await pool.query("SELECT state FROM game_saves WHERE google_sub=$1", [req.user.sub]);
  if (!trusted.rows[0]) return res.status(409).json({ error: "save must exist before joining house" });
  const state = trusted.rows[0].state, raw = req.body?.profile || {};
  const profile = {
    code: String(state.account?.code || "").slice(0,10).toUpperCase(), name: String(state.player?.name || "ผู้เล่น").slice(0,24),
    x: clamp(num(raw.x,100),0,216), dir: num(raw.dir,1)<0?-1:1,
    state: ["idle","walk","sit","focus"].includes(raw.state)?raw.state:"idle", focus:Boolean(raw.focus), look:state.player||{},
    zone: ["home","yard","garden"].includes(raw.zone) ? raw.zone
      : (["home","yard","garden"].includes(state.area) ? state.area : "away"),
    pet:{name:String(state.pet?.name||"Mori").slice(0,24),form:String(state.pet?.form||"seed").slice(0,24),lv:clamp(Math.round(num(state.pet?.lv,1)),1,100)}
  };
  const db=await pool.connect();
  try {
    await db.query("BEGIN");await db.query("SELECT pg_advisory_xact_lock(hashtext($1))",[`house:${code}`]);
    await db.query("DELETE FROM room_presence WHERE seen_at < NOW()-INTERVAL '20 seconds'");
    const owner=await db.query("SELECT google_sub,state FROM game_saves WHERE UPPER(state->'account'->>'code')=$1 LIMIT 1",[code]);
    if(!owner.rows[0]){await db.query("ROLLBACK");return res.status(404).json({error:"house not found"});}
    if(owner.rows[0].google_sub===req.user.sub) profile.house=cleanHouse(raw.house,owner.rows[0].state);
    if(owner.rows[0].google_sub!==req.user.sub){if(owner.rows[0].state?.houseLocked){await db.query("ROLLBACK");return res.status(423).json({error:"house locked"});}const online=await db.query("SELECT profile FROM room_presence WHERE room_code=$1 AND google_sub=$2",[code,owner.rows[0].google_sub]);if(!online.rowCount||!["home","yard","garden"].includes(online.rows[0].profile?.zone)){await db.query("ROLLBACK");return res.status(409).json({error:"friend is not home"});}}
    const count=await db.query("SELECT COUNT(*)::int AS n FROM room_presence WHERE room_code=$1 AND google_sub<>$2",[code,req.user.sub]);
    if(count.rows[0].n>=5){await db.query("ROLLBACK");return res.status(409).json({error:"house full"});}
    await db.query("DELETE FROM room_presence WHERE google_sub=$1",[req.user.sub]);
    await db.query("INSERT INTO room_presence(room_code,google_sub,profile,seen_at) VALUES($1,$2,$3,NOW()) ON CONFLICT(room_code,google_sub) DO UPDATE SET profile=EXCLUDED.profile,seen_at=NOW()",[code,req.user.sub,profile]);
    await db.query("COMMIT");res.json(await roomState(code,req.body?.after));
  }catch(error){await db.query("ROLLBACK").catch(()=>{});throw error;}finally{db.release();}
});
app.get("/api/rooms/:code/presence", requireUser, async (req, res) => {
  const code=String(req.params.code||"").toUpperCase();if(!/^[A-Z0-9]{4,10}$/.test(code))return res.status(400).json({error:"invalid room"});
  res.json(await roomState(code,req.query.after));
});
app.post("/api/rooms/:code/chat", rateLimit("house-chat",6,10_000), requireUser, async(req,res)=>{
  const code=String(req.params.code||"").toUpperCase();const member=await pool.query("SELECT profile FROM room_presence WHERE room_code=$1 AND google_sub=$2 AND seen_at>NOW()-INTERVAL '20 seconds'",[code,req.user.sub]);
  if(!member.rows[0])return res.status(403).json({error:"not in house"});let message=String(req.body?.message||"").replace(/[<>\u0000-\u001f]/g,"").trim().slice(0,140).replace(/(ควย|เหี้ย|เย็ด|fuck|shit)/gi,"***");
  if(!message)return res.status(400).json({error:"empty message"});await pool.query("INSERT INTO room_messages(room_code,google_sub,name,message) VALUES($1,$2,$3,$4)",[code,req.user.sub,member.rows[0].profile.name,message]);res.json({ok:true});
});
app.delete("/api/rooms/:code/presence", requireUser, async (req, res) => {
  await pool.query("DELETE FROM room_presence WHERE room_code=$1 AND google_sub=$2", [String(req.params.code || "").toUpperCase(), req.user.sub]);
  res.json({ ok: true });
});

const cleanText = (value, max) => String(value || "").replace(/[<>\u0000-\u001f]/g, "").trim().slice(0, max);
const cleanPlazaProfile = (raw, trusted = null) => ({
  code: cleanText(trusted?.account?.code || raw?.code, 10).toUpperCase(),
  name: cleanText(trusted?.player?.name || raw?.name, 24) || "ผู้เล่น",
  x: clamp(Math.round(num(raw?.x, 50)), 4, 96),
  y: clamp(Math.round(num(raw?.y, 68)), 24, 86),
  dir: num(raw?.dir, 1) < 0 ? -1 : 1,
  look: trusted?.player && typeof trusted.player === "object" ? trusted.player : (raw?.look && typeof raw.look === "object" ? raw.look : {}),
  pet: { name: cleanText(trusted?.pet?.name || raw?.pet?.name, 24) || "Mori", form: cleanText(trusted?.pet?.form || raw?.pet?.form, 24) || "seed", lv: clamp(Math.round(num(trusted?.pet?.lv ?? raw?.pet?.lv, 1)), 1, 100) }
});
async function plazaState(channel, after = 0) {
  await pool.query("DELETE FROM plaza_presence WHERE seen_at < NOW() - INTERVAL '18 seconds'");
  const [members, messages] = await Promise.all([
    pool.query("SELECT profile FROM plaza_presence WHERE channel=$1 ORDER BY seen_at DESC LIMIT 30", [channel]),
    pool.query(`SELECT id,name,message,created_at FROM plaza_messages
      WHERE channel=$1 AND id>$2 ORDER BY id DESC LIMIT 50`, [channel, Math.max(0, Number(after) || 0)])
  ]);
  return { channel, members: members.rows.map(r => r.profile), messages: messages.rows.reverse() };
}
app.get("/api/plaza/channels", requireUser, async (_req, res) => {
  await pool.query("DELETE FROM plaza_presence WHERE seen_at < NOW() - INTERVAL '18 seconds'");
  const counts = await pool.query("SELECT channel,COUNT(*)::int AS players FROM plaza_presence GROUP BY channel ORDER BY channel");
  const map = new Map(counts.rows.map(r => [Number(r.channel), r.players]));
  const last = Math.max(3, ...map.keys());
  res.json({ channels: Array.from({ length: last }, (_, i) => ({ channel: i + 1, players: map.get(i + 1) || 0, capacity: 30 })) });
});
app.post("/api/plaza/join", rateLimit("plaza-join", 12), requireUser, async (req, res) => {
  const trustedSave = await pool.query("SELECT state FROM game_saves WHERE google_sub=$1", [req.user.sub]);
  if (!trustedSave.rows[0]) return res.status(409).json({ error: "save must exist before joining plaza" });
  const profile = cleanPlazaProfile(req.body?.profile, trustedSave.rows[0].state);
  const requested = clamp(Math.round(num(req.body?.channel, 0)), 0, 99);
  const db = await pool.connect();
  try {
    await db.query("BEGIN");
    await db.query("DELETE FROM plaza_presence WHERE seen_at < NOW() - INTERVAL '18 seconds'");
    let channel = requested;
    if (!channel) {
      const counts = await db.query("SELECT channel,COUNT(*)::int AS n FROM plaza_presence GROUP BY channel ORDER BY channel");
      const map = new Map(counts.rows.map(r => [Number(r.channel), r.n]));
      channel = 1; while ((map.get(channel) || 0) >= 30 && channel < 99) channel += 1;
    }
    await db.query("SELECT pg_advisory_xact_lock($1)", [900000 + channel]);
    const count = await db.query("SELECT COUNT(*)::int AS n FROM plaza_presence WHERE channel=$1 AND google_sub<>$2", [channel, req.user.sub]);
    if (count.rows[0].n >= 30) { await db.query("ROLLBACK"); return res.status(409).json({ error: "channel full" }); }
    await db.query("DELETE FROM plaza_presence WHERE google_sub=$1", [req.user.sub]);
    await db.query("INSERT INTO plaza_presence (channel,google_sub,profile,seen_at) VALUES ($1,$2,$3,NOW())", [channel, req.user.sub, profile]);
    await db.query("COMMIT");
    res.json(await plazaState(channel));
  } catch (error) { await db.query("ROLLBACK").catch(() => {}); throw error; } finally { db.release(); }
});
app.put("/api/plaza/:channel/presence", rateLimit("plaza-presence", 45), requireUser, async (req, res) => {
  const channel = clamp(Math.round(num(req.params.channel, 0)), 1, 99);
  const current = await pool.query("SELECT profile FROM plaza_presence WHERE channel=$1 AND google_sub=$2", [channel, req.user.sub]);
  if (!current.rows[0]) return res.status(409).json({ error: "join plaza first" });
  const movement = cleanPlazaProfile(req.body?.profile);
  const profile = { ...current.rows[0].profile, x: movement.x, y: movement.y, dir: movement.dir };
  const updated = await pool.query(`UPDATE plaza_presence SET profile=$3,seen_at=NOW()
    WHERE channel=$1 AND google_sub=$2 RETURNING google_sub`, [channel, req.user.sub, profile]);
  if (!updated.rowCount) return res.status(409).json({ error: "join plaza first" });
  res.json(await plazaState(channel, req.body?.after));
});
app.get("/api/plaza/:channel/state", requireUser, async (req, res) => {
  const channel = clamp(Math.round(num(req.params.channel, 0)), 1, 99);
  res.json(await plazaState(channel, req.query.after));
});
app.post("/api/plaza/:channel/chat", rateLimit("plaza-chat", 6, 10_000), requireUser, async (req, res) => {
  const channel = clamp(Math.round(num(req.params.channel, 0)), 1, 99);
  const member = await pool.query("SELECT profile FROM plaza_presence WHERE channel=$1 AND google_sub=$2 AND seen_at>NOW()-INTERVAL '18 seconds'", [channel, req.user.sub]);
  if (!member.rows[0]) return res.status(403).json({ error: "not in channel" });
  let message = cleanText(req.body?.message, 140).replace(/(ควย|เหี้ย|เย็ด|fuck|shit)/gi, "***");
  if (!message) return res.status(400).json({ error: "empty message" });
  await pool.query("INSERT INTO plaza_messages (channel,google_sub,name,message) VALUES ($1,$2,$3,$4)", [channel, req.user.sub, member.rows[0].profile.name, message]);
  res.json({ ok: true });
});
app.delete("/api/plaza/:channel/presence", requireUser, async (req, res) => {
  await pool.query("DELETE FROM plaza_presence WHERE google_sub=$1", [req.user.sub]);
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
await pool.query(`CREATE TABLE IF NOT EXISTS room_messages (
  id BIGSERIAL PRIMARY KEY,
  room_code TEXT NOT NULL,
  google_sub TEXT NOT NULL,
  name TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`);
await pool.query("CREATE INDEX IF NOT EXISTS room_messages_room_id ON room_messages (room_code,id DESC)");
await pool.query(`CREATE TABLE IF NOT EXISTS security_events (
  id BIGSERIAL PRIMARY KEY,
  google_sub TEXT NOT NULL,
  email TEXT NOT NULL,
  kind TEXT NOT NULL,
  severity SMALLINT NOT NULL DEFAULT 1,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`);
await pool.query("CREATE INDEX IF NOT EXISTS security_events_user_time ON security_events (google_sub, created_at DESC)");
await pool.query(`CREATE TABLE IF NOT EXISTS focus_sessions (
  token UUID PRIMARY KEY,
  google_sub TEXT NOT NULL,
  planned_minutes INTEGER NOT NULL,
  difficulty TEXT NOT NULL,
  mode TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  credited_minutes DOUBLE PRECISION,
  coins_awarded INTEGER
)`);
await pool.query("CREATE INDEX IF NOT EXISTS focus_sessions_user_time ON focus_sessions (google_sub, started_at DESC)");
await pool.query(`CREATE TABLE IF NOT EXISTS plaza_presence (
  channel INTEGER NOT NULL,
  google_sub TEXT NOT NULL UNIQUE,
  profile JSONB NOT NULL,
  seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (channel, google_sub)
)`);
await pool.query("CREATE INDEX IF NOT EXISTS plaza_presence_channel_time ON plaza_presence (channel, seen_at DESC)");
await pool.query(`CREATE TABLE IF NOT EXISTS plaza_messages (
  id BIGSERIAL PRIMARY KEY,
  channel INTEGER NOT NULL,
  google_sub TEXT NOT NULL,
  name TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`);
await pool.query("CREATE INDEX IF NOT EXISTS plaza_messages_channel_id ON plaza_messages (channel, id DESC)");
await pool.query(`CREATE TABLE IF NOT EXISTS economy_events (
  id BIGSERIAL PRIMARY KEY,
  google_sub TEXT NOT NULL,
  kind TEXT NOT NULL,
  amount INTEGER NOT NULL,
  reference TEXT,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (google_sub, kind, reference)
)`);
await pool.query(`CREATE TABLE IF NOT EXISTS account_activity (
  google_sub TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  last_ip TEXT,
  last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`);
await pool.query(`CREATE TABLE IF NOT EXISTS ip_blocks (
  ip TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`);
await pool.query(`CREATE TABLE IF NOT EXISTS active_sessions (
  google_sub TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`);
await pool.query(`CREATE TABLE IF NOT EXISTS friend_cheers (
  sender_sub TEXT NOT NULL,
  target_sub TEXT NOT NULL,
  sent_on DATE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (sender_sub,target_sub,sent_on)
)`);
await pool.query(`CREATE TABLE IF NOT EXISTS collectible_ids (
  id VARCHAR(13) PRIMARY KEY, google_sub TEXT NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (google_sub,kind,ref)
)`);
app.listen(port, "0.0.0.0", () => console.log(`SAMATI listening on ${port}`));
