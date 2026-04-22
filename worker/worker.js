// hadfield-worker — Time Tracker backend for Hadfield Properties LLC
//
// Routes:
//   GET  /health                        — liveness / config check
//   GET  /api/worker/workers            — list active workers (name screen, no auth)
//   POST /api/worker/verify-pin         — verify PIN, set worker_session cookie
//   POST /api/worker/logout             — clear worker_session cookie
//   GET  /api/worker/context            — list jobsites + tasks (auth)
//   GET  /api/worker/status             — current clock status for session worker (auth)
//   POST /api/worker/clock-in           — clock in (auth)
//   POST /api/worker/clock-out          — clock out (auth)
//
//   Admin routes (Cloudflare Access JWT required):
//   GET  /api/admin/whoami
//   GET  /api/admin/dashboard
//   GET  /api/admin/workers             CRUD: POST / PATCH / DELETE
//   GET  /api/admin/jobsites            CRUD
//   GET  /api/admin/tasks               CRUD
//   GET  /api/admin/entries             — list entries with filters
//   POST /api/admin/entries             — add missing punch
//   PATCH /api/admin/entries/:id        — edit entry (audit-logged)
//   DELETE /api/admin/entries/:id       — delete entry (audit-logged)
//   GET  /api/admin/entries/:id/audit   — audit trail for one entry
//   GET  /api/admin/export/csv          — QuickBooks CSV
//   GET  /api/admin/settings            GET/PATCH
//
//   Billing routes (Cloudflare Access JWT required, EXCEPT the webhook):
//   GET  /api/billing/status                 — current subscription state
//   POST /api/billing/setup-intent           — create Stripe SetupIntent for new card
//   POST /api/billing/confirm-subscription   — attach card + create/update subscription
//   POST /api/billing/update-card            — collect a new card (reuses setup-intent flow)
//   POST /api/billing/cancel                 — cancel at period end
//   POST /api/stripe/webhook                 — Stripe event hook (verified by HMAC signature, NOT CF Access)
//
// Auth:
//   Worker side: pick name → /verify-pin returns a signed cookie (HS256 JWT, 12h).
//   Admin side: Cloudflare Access TOTP 2FA. We trust Cf-Access-Jwt-Assertion and
//   verify against CF_ACCESS_AUD + JWKS from the team domain. ADMIN_EMAILS is a
//   belt-and-suspenders allowlist.
//   Stripe webhook: CF Access must NOT protect /api/stripe/*. Signature
//   verification happens in code using STRIPE_WEBHOOK_SECRET.

// ─── Utilities ───────────────────────────────────────────────────────────────

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64url(bytes) {
  let s = btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Hex(str) {
  const hash = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomHex(n = 16) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return [...buf].map(b => b.toString(16).padStart(2, '0')).join('');
}

function json(obj, init = {}) {
  return new Response(JSON.stringify(obj), {
    status: init.status || 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...(init.headers || {}),
    },
  });
}

function err(status, message) {
  return json({ error: message }, { status });
}

function getCookie(req, name) {
  const cookie = req.headers.get('cookie') || '';
  const m = cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}

function cookieHeader(name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push('Path=/');
  parts.push('HttpOnly');
  parts.push('Secure');
  parts.push('SameSite=Lax');
  if (opts.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.expires === 0) parts.push('Max-Age=0');
  return parts.join('; ');
}

// ─── HMAC-SHA256 JWT (worker_session) ────────────────────────────────────────

async function signJwt(payload, secret, ttlSec = 12 * 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = { iat: now, exp: now + ttlSec, ...payload };
  const h = b64url(enc.encode(JSON.stringify(header)));
  const b = b64url(enc.encode(JSON.stringify(body)));
  const data = `${h}.${b}`;
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return `${data}.${b64url(sig)}`;
}

async function verifyJwt(token, secret) {
  try {
    const [h, b, s] = token.split('.');
    if (!h || !b || !s) return null;
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const ok = await crypto.subtle.verify('HMAC', key, b64urlDecode(s), enc.encode(`${h}.${b}`));
    if (!ok) return null;
    const payload = JSON.parse(dec.decode(b64urlDecode(b)));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// ─── CF Access JWT verification ──────────────────────────────────────────────

let jwksCache = { keys: null, ts: 0 };
async function getJwks(teamDomain) {
  const now = Date.now();
  if (jwksCache.keys && now - jwksCache.ts < 60 * 60 * 1000) return jwksCache.keys;
  const r = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
  const data = await r.json();
  jwksCache = { keys: data.keys || [], ts: now };
  return jwksCache.keys;
}

async function verifyAccessJwt(token, env) {
  try {
    let team = env.CF_ACCESS_TEAM;
    const aud = env.CF_ACCESS_AUD;
    if (!team || !aud) return { _reason: 'missing CF_ACCESS_TEAM or CF_ACCESS_AUD' };
    // Be forgiving about accidental https:// prefix or trailing slash
    team = team.replace(/^https?:\/\//, '').replace(/\/+$/, '').trim();
    const [h, b, s] = token.split('.');
    if (!h || !b || !s) return { _reason: 'token not a JWT (wrong number of segments)' };
    let header, payload;
    try {
      header = JSON.parse(dec.decode(b64urlDecode(h)));
      payload = JSON.parse(dec.decode(b64urlDecode(b)));
    } catch { return { _reason: 'could not decode JWT header/payload' }; }
    if (payload.aud !== aud && !(Array.isArray(payload.aud) && payload.aud.includes(aud))) {
      return { _reason: `aud mismatch (token aud=${JSON.stringify(payload.aud)}, expected ${aud})` };
    }
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return { _reason: 'token expired' };

    const jwks = await getJwks(team);
    const jwk = jwks.find(k => k.kid === header.kid);
    if (!jwk) return { _reason: `no matching jwk for kid ${header.kid}` };
    const key = await crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
    );
    const ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5', key,
      b64urlDecode(s), enc.encode(`${h}.${b}`)
    );
    if (!ok) return { _reason: 'signature did not verify' };
    return payload;
  } catch (e) {
    return { _reason: `verify threw: ${e.message || e}` };
  }
}

// ─── Auth guards ─────────────────────────────────────────────────────────────

async function requireWorkerSession(req, env) {
  const token = getCookie(req, 'worker_session');
  if (!token) return null;
  const payload = await verifyJwt(token, env.WORKER_SESSION_SECRET);
  if (!payload || !payload.wid) return null;
  return { worker_id: payload.wid, worker_name: payload.name };
}

async function requireAdmin(req, env) {
  const token = req.headers.get('cf-access-jwt-assertion') || getCookie(req, 'CF_Authorization');
  if (!token) return { ok: false, status: 401, msg: 'No CF Access token' };
  const payload = await verifyAccessJwt(token, env);
  if (!payload) return { ok: false, status: 401, msg: 'Invalid CF Access token' };
  if (payload._reason) return { ok: false, status: 401, msg: `Invalid CF Access token: ${payload._reason}` };
  const email = (payload.email || payload.identity_nonce || '').toLowerCase();
  const allowed = (env.ADMIN_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  if (allowed.length > 0 && !allowed.includes(email)) {
    return { ok: false, status: 403, msg: `Not in admin allowlist: ${email}` };
  }
  return { ok: true, email };
}

// ─── DB helpers ──────────────────────────────────────────────────────────────

async function pickWorkerActive(env, workerId) {
  const r = await env.HADFIELD_DB
    .prepare('SELECT id, clock_in FROM time_entries WHERE worker_id = ? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1')
    .bind(workerId).first();
  return r || null;
}

// ─── Stripe helpers ──────────────────────────────────────────────────────────
// Ported from the main appsforhire-worker so both workers use the same proven
// signature check. Stripe sends a `Stripe-Signature: t=...,v1=...` header; we
// HMAC-SHA256 "<t>.<rawBody>" with the webhook secret and compare to v1.

async function verifyStripeSignature(payload, sigHeader, secret) {
  try {
    const parts = Object.fromEntries(sigHeader.split(',').map(p => p.split('=')));
    const { t: timestamp, v1: signature } = parts;
    if (!timestamp || !signature) return false;

    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const signed = await crypto.subtle.sign('HMAC', key, enc.encode(`${timestamp}.${payload}`));
    const expected = Array.from(new Uint8Array(signed))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    return expected === signature;
  } catch {
    return false;
  }
}

// Stripe's REST API takes application/x-www-form-urlencoded bodies with bracket
// notation for nested objects/arrays: `metadata[foo]=bar`, `items[0][price]=...`.
function stripeFormEncode(obj, prefix = '') {
  const parts = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined) continue;
    const key = prefix ? `${prefix}[${k}]` : k;
    if (Array.isArray(v)) {
      v.forEach((item, i) => {
        const arrKey = `${key}[${i}]`;
        if (item !== null && typeof item === 'object') {
          parts.push(stripeFormEncode(item, arrKey));
        } else {
          parts.push(`${encodeURIComponent(arrKey)}=${encodeURIComponent(item)}`);
        }
      });
    } else if (typeof v === 'object') {
      parts.push(stripeFormEncode(v, key));
    } else {
      parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(v)}`);
    }
  }
  return parts.join('&');
}

async function stripeApi(env, method, path, bodyParams) {
  if (!env.STRIPE_SECRET_KEY) throw new Error('STRIPE_SECRET_KEY not configured');
  const init = {
    method,
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` },
  };
  if (bodyParams) {
    init.body = stripeFormEncode(bodyParams);
    init.headers['content-type'] = 'application/x-www-form-urlencoded';
  }
  const r = await fetch(`https://api.stripe.com${path}`, init);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = data?.error?.message || `Stripe ${r.status}`;
    const e = new Error(`Stripe ${method} ${path} failed: ${msg}`);
    e.status = r.status;
    e.stripeError = data?.error || null;
    throw e;
  }
  return data;
}

// ─── Billing state (stored as one JSON blob in HADFIELD_KV) ──────────────────

const BILLING_KV_KEY = 'billing:state';

const EMPTY_BILLING_STATE = {
  customer_id: null,
  subscription_id: null,
  status: 'none',                 // none | trialing | active | past_due | canceled | unpaid
  current_period_end: null,       // unix seconds
  cancel_at_period_end: false,
  last_invoice_id: null,
  updated_at: null,
};

async function getBillingState(env) {
  const raw = await env.HADFIELD_KV.get(BILLING_KV_KEY);
  if (!raw) return { ...EMPTY_BILLING_STATE };
  try { return { ...EMPTY_BILLING_STATE, ...JSON.parse(raw) }; }
  catch { return { ...EMPTY_BILLING_STATE }; }
}

async function setBillingState(env, patch) {
  const current = await getBillingState(env);
  const next = { ...current, ...patch, updated_at: Math.floor(Date.now() / 1000) };
  await env.HADFIELD_KV.put(BILLING_KV_KEY, JSON.stringify(next));
  return next;
}

// ─── Route handlers ──────────────────────────────────────────────────────────

async function handleHealth(env) {
  const checks = {
    ok: true,
    db: !!env.HADFIELD_DB,
    kv: !!env.HADFIELD_KV,
    r2: !!env.HADFIELD_ASSETS,
    secrets: {
      WORKER_SESSION_SECRET: !!env.WORKER_SESSION_SECRET,
      CF_ACCESS_AUD: !!env.CF_ACCESS_AUD,
      CF_ACCESS_TEAM: !!env.CF_ACCESS_TEAM,
      ADMIN_EMAILS: !!env.ADMIN_EMAILS,
      STRIPE_SECRET_KEY:      !!env.STRIPE_SECRET_KEY,
      STRIPE_PUBLISHABLE_KEY: !!env.STRIPE_PUBLISHABLE_KEY,
      STRIPE_PRICE_FAMILY:    !!env.STRIPE_PRICE_FAMILY,
      STRIPE_WEBHOOK_SECRET:  !!env.STRIPE_WEBHOOK_SECRET,
    },
    ts: Date.now(),
  };
  try {
    const r = await env.HADFIELD_DB.prepare('SELECT COUNT(*) as n FROM workers').first();
    checks.workers_count = r?.n ?? 0;
  } catch (e) { checks.db_error = String(e); checks.ok = false; }
  return json(checks);
}

// --- Worker-facing routes ----------------------------------------------------

async function listActiveWorkers(env) {
  const { results } = await env.HADFIELD_DB
    .prepare('SELECT id, full_name FROM workers WHERE active = 1 ORDER BY full_name ASC')
    .all();
  return json({ workers: results });
}

async function verifyPin(req, env) {
  const body = await req.json().catch(() => ({}));
  const { worker_id, pin } = body;
  if (!worker_id || !pin || !/^\d{4}$/.test(String(pin))) {
    return err(400, 'worker_id and 4-digit pin required');
  }
  const w = await env.HADFIELD_DB
    .prepare('SELECT id, full_name, pin_hash, pin_salt, active FROM workers WHERE id = ?')
    .bind(worker_id).first();
  if (!w || !w.active) return err(404, 'Worker not found');
  const calc = await sha256Hex(String(pin) + w.pin_salt);
  if (calc !== w.pin_hash) return err(401, 'Wrong PIN');

  const token = await signJwt({ wid: w.id, name: w.full_name }, env.WORKER_SESSION_SECRET, 12 * 3600);
  return new Response(JSON.stringify({ worker_id: w.id, full_name: w.full_name }), {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'set-cookie': cookieHeader('worker_session', token, { maxAge: 12 * 3600 }),
    },
  });
}

function workerLogout() {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'set-cookie': cookieHeader('worker_session', '', { expires: 0 }),
    },
  });
}

async function workerContext(req, env) {
  const sess = await requireWorkerSession(req, env);
  if (!sess) return err(401, 'Session expired');
  const [jobs, tasks] = await Promise.all([
    env.HADFIELD_DB.prepare('SELECT id, name, address FROM jobsites WHERE active = 1 ORDER BY name').all(),
    env.HADFIELD_DB.prepare('SELECT id, name FROM tasks WHERE active = 1 ORDER BY name').all(),
  ]);
  return json({
    worker: sess,
    jobsites: jobs.results,
    tasks: tasks.results,
  });
}

async function workerStatus(req, env) {
  const sess = await requireWorkerSession(req, env);
  if (!sess) return err(401, 'Session expired');
  const active = await env.HADFIELD_DB.prepare(
    `SELECT e.id, e.clock_in, e.notes,
            j.name AS jobsite_name, t.name AS task_name
       FROM time_entries e
       LEFT JOIN jobsites j ON j.id = e.jobsite_id
       LEFT JOIN tasks t    ON t.id = e.task_id
      WHERE e.worker_id = ? AND e.clock_out IS NULL
      ORDER BY e.clock_in DESC LIMIT 1`
  ).bind(sess.worker_id).first();
  return json({ worker: sess, active_entry: active || null });
}

async function workerClockIn(req, env) {
  const sess = await requireWorkerSession(req, env);
  if (!sess) return err(401, 'Session expired');
  const body = await req.json().catch(() => ({}));
  const { jobsite_id, task_id, notes, lat, lng, accuracy } = body;
  if (!jobsite_id || !task_id) return err(400, 'jobsite_id and task_id are required');

  // Refuse if already clocked in
  const open = await pickWorkerActive(env, sess.worker_id);
  if (open) return err(409, 'Already clocked in');

  const now = Date.now();
  const ins = await env.HADFIELD_DB.prepare(
    `INSERT INTO time_entries
      (worker_id, jobsite_id, task_id, clock_in, clock_in_lat, clock_in_lng, clock_in_accuracy, notes, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    sess.worker_id, jobsite_id, task_id, now,
    lat ?? null, lng ?? null, accuracy ?? null,
    notes ? String(notes).slice(0, 500) : null,
    now,
  ).run();
  return json({ ok: true, entry_id: ins.meta.last_row_id, clock_in: now });
}

async function workerClockOut(req, env) {
  const sess = await requireWorkerSession(req, env);
  if (!sess) return err(401, 'Session expired');
  const body = await req.json().catch(() => ({}));
  const { lat, lng, accuracy, notes } = body;

  const open = await pickWorkerActive(env, sess.worker_id);
  if (!open) return err(409, 'Not clocked in');

  const now = Date.now();
  await env.HADFIELD_DB.prepare(
    `UPDATE time_entries
        SET clock_out = ?, clock_out_lat = ?, clock_out_lng = ?, clock_out_accuracy = ?,
            notes = COALESCE(?, notes)
      WHERE id = ?`
  ).bind(
    now, lat ?? null, lng ?? null, accuracy ?? null,
    notes ? String(notes).slice(0, 500) : null,
    open.id,
  ).run();
  return json({ ok: true, entry_id: open.id, clock_out: now });
}

// --- Admin routes ------------------------------------------------------------

async function adminWhoami(req, env) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);
  return json({ email: a.email });
}

async function adminDashboard(req, env) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);

  const now = Date.now();
  const longShiftMs = 12 * 3600 * 1000;
  const dayMs = 24 * 3600 * 1000;

  const live = await env.HADFIELD_DB.prepare(
    `SELECT e.id, e.clock_in, w.full_name, j.name AS jobsite, t.name AS task
       FROM time_entries e
       JOIN workers w  ON w.id = e.worker_id
       LEFT JOIN jobsites j ON j.id = e.jobsite_id
       LEFT JOIN tasks t    ON t.id = e.task_id
      WHERE e.clock_out IS NULL
      ORDER BY e.clock_in DESC`
  ).all();

  const todayStart = now - (now % dayMs);
  const today = await env.HADFIELD_DB.prepare(
    `SELECT w.id AS worker_id, w.full_name,
            COALESCE(SUM(COALESCE(e.clock_out, ?) - e.clock_in), 0) AS ms
       FROM workers w
       LEFT JOIN time_entries e ON e.worker_id = w.id AND e.clock_in >= ?
      WHERE w.active = 1
      GROUP BY w.id
      ORDER BY ms DESC`
  ).bind(now, todayStart).all();

  const weekStart = now - 7 * dayMs;
  const week = await env.HADFIELD_DB.prepare(
    `SELECT w.id AS worker_id, w.full_name,
            COALESCE(SUM(COALESCE(e.clock_out, ?) - e.clock_in), 0) AS ms
       FROM workers w
       LEFT JOIN time_entries e ON e.worker_id = w.id AND e.clock_in >= ?
      WHERE w.active = 1
      GROUP BY w.id
      ORDER BY ms DESC`
  ).bind(now, weekStart).all();

  const anomalies = await env.HADFIELD_DB.prepare(
    `SELECT e.id, e.clock_in, w.full_name, j.name AS jobsite
       FROM time_entries e
       JOIN workers w ON w.id = e.worker_id
       LEFT JOIN jobsites j ON j.id = e.jobsite_id
      WHERE e.clock_out IS NULL AND (? - e.clock_in) > ?`
  ).bind(now, longShiftMs).all();

  return json({
    now,
    live: live.results,
    today: today.results,
    week: week.results,
    anomalies: anomalies.results,
  });
}

// ---- Workers CRUD ----

async function adminWorkers(req, env, method) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);

  if (method === 'GET') {
    const { results } = await env.HADFIELD_DB.prepare(
      'SELECT id, full_name, phone, hourly_rate, qb_employee_id, active FROM workers ORDER BY active DESC, full_name'
    ).all();
    return json({ workers: results });
  }

  if (method === 'POST') {
    const body = await req.json().catch(() => ({}));
    const { full_name, phone, pin, hourly_rate, qb_employee_id } = body;
    if (!full_name || !pin || !/^\d{4}$/.test(String(pin))) return err(400, 'full_name and 4-digit pin required');
    const salt = randomHex(16);
    const hash = await sha256Hex(String(pin) + salt);
    const res = await env.HADFIELD_DB.prepare(
      `INSERT INTO workers (full_name, phone, pin_hash, pin_salt, hourly_rate, qb_employee_id, active, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 1, ?)`
    ).bind(
      full_name.trim(), phone || null, hash, salt,
      hourly_rate != null ? Number(hourly_rate) : null,
      qb_employee_id || null, Date.now(),
    ).run();
    return json({ id: res.meta.last_row_id });
  }
  return err(405, 'Method not allowed');
}

async function adminWorkerOne(req, env, id, method) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);

  if (method === 'PATCH') {
    const body = await req.json().catch(() => ({}));
    const sets = [];
    const vals = [];
    if (body.full_name != null) { sets.push('full_name = ?'); vals.push(String(body.full_name).trim()); }
    if (body.phone != null)     { sets.push('phone = ?'); vals.push(body.phone || null); }
    if (body.hourly_rate != null) { sets.push('hourly_rate = ?'); vals.push(Number(body.hourly_rate)); }
    if (body.qb_employee_id != null) { sets.push('qb_employee_id = ?'); vals.push(body.qb_employee_id || null); }
    if (body.active != null)    { sets.push('active = ?'); vals.push(body.active ? 1 : 0); }
    if (body.pin != null) {
      if (!/^\d{4}$/.test(String(body.pin))) return err(400, 'pin must be 4 digits');
      const salt = randomHex(16);
      const hash = await sha256Hex(String(body.pin) + salt);
      sets.push('pin_hash = ?'); vals.push(hash);
      sets.push('pin_salt = ?'); vals.push(salt);
    }
    if (!sets.length) return err(400, 'No fields to update');
    vals.push(id);
    await env.HADFIELD_DB.prepare(`UPDATE workers SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
    return json({ ok: true });
  }

  if (method === 'DELETE') {
    // Soft-delete: just mark inactive to preserve history
    await env.HADFIELD_DB.prepare('UPDATE workers SET active = 0 WHERE id = ?').bind(id).run();
    return json({ ok: true });
  }
  return err(405, 'Method not allowed');
}

// ---- Jobsites CRUD ----

async function adminJobsites(req, env, method) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);

  if (method === 'GET') {
    const { results } = await env.HADFIELD_DB.prepare(
      'SELECT id, name, address, lat, lng, active FROM jobsites ORDER BY active DESC, name'
    ).all();
    return json({ jobsites: results });
  }
  if (method === 'POST') {
    const body = await req.json().catch(() => ({}));
    const { name, address, lat, lng } = body;
    if (!name) return err(400, 'name required');
    const res = await env.HADFIELD_DB.prepare(
      'INSERT INTO jobsites (name, address, lat, lng, active) VALUES (?, ?, ?, ?, 1)'
    ).bind(name.trim(), address || null, lat ?? null, lng ?? null).run();
    return json({ id: res.meta.last_row_id });
  }
  return err(405, 'Method not allowed');
}

async function adminJobsiteOne(req, env, id, method) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);
  if (method === 'PATCH') {
    const body = await req.json().catch(() => ({}));
    const sets = [], vals = [];
    for (const k of ['name', 'address', 'lat', 'lng']) {
      if (body[k] != null) { sets.push(`${k} = ?`); vals.push(body[k]); }
    }
    if (body.active != null) { sets.push('active = ?'); vals.push(body.active ? 1 : 0); }
    if (!sets.length) return err(400, 'No fields to update');
    vals.push(id);
    await env.HADFIELD_DB.prepare(`UPDATE jobsites SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
    return json({ ok: true });
  }
  if (method === 'DELETE') {
    await env.HADFIELD_DB.prepare('UPDATE jobsites SET active = 0 WHERE id = ?').bind(id).run();
    return json({ ok: true });
  }
  return err(405, 'Method not allowed');
}

// ---- Tasks CRUD ----

async function adminTasks(req, env, method) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);
  if (method === 'GET') {
    const { results } = await env.HADFIELD_DB.prepare(
      'SELECT id, name, qb_service_item, active FROM tasks ORDER BY active DESC, name'
    ).all();
    return json({ tasks: results });
  }
  if (method === 'POST') {
    const body = await req.json().catch(() => ({}));
    const { name, qb_service_item } = body;
    if (!name) return err(400, 'name required');
    const res = await env.HADFIELD_DB.prepare(
      'INSERT INTO tasks (name, qb_service_item, active) VALUES (?, ?, 1)'
    ).bind(name.trim(), qb_service_item || null).run();
    return json({ id: res.meta.last_row_id });
  }
  return err(405, 'Method not allowed');
}

async function adminTaskOne(req, env, id, method) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);
  if (method === 'PATCH') {
    const body = await req.json().catch(() => ({}));
    const sets = [], vals = [];
    if (body.name != null) { sets.push('name = ?'); vals.push(String(body.name).trim()); }
    if (body.qb_service_item != null) { sets.push('qb_service_item = ?'); vals.push(body.qb_service_item || null); }
    if (body.active != null) { sets.push('active = ?'); vals.push(body.active ? 1 : 0); }
    if (!sets.length) return err(400, 'No fields to update');
    vals.push(id);
    await env.HADFIELD_DB.prepare(`UPDATE tasks SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
    return json({ ok: true });
  }
  if (method === 'DELETE') {
    await env.HADFIELD_DB.prepare('UPDATE tasks SET active = 0 WHERE id = ?').bind(id).run();
    return json({ ok: true });
  }
  return err(405, 'Method not allowed');
}

// ---- Entries (listing, edit, add missing, delete) ----

async function adminEntries(req, env, method) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);

  if (method === 'GET') {
    const u = new URL(req.url);
    const from = Number(u.searchParams.get('from') || 0);
    const to   = Number(u.searchParams.get('to') || Date.now());
    const worker = u.searchParams.get('worker_id');
    const jobsite = u.searchParams.get('jobsite_id');
    const task = u.searchParams.get('task_id');

    let sql = `SELECT e.*,
                      w.full_name AS worker_name,
                      j.name AS jobsite_name,
                      t.name AS task_name
                 FROM time_entries e
                 JOIN workers w  ON w.id = e.worker_id
                 LEFT JOIN jobsites j ON j.id = e.jobsite_id
                 LEFT JOIN tasks t    ON t.id = e.task_id
                WHERE e.clock_in >= ? AND e.clock_in <= ?`;
    const params = [from, to];
    if (worker)  { sql += ' AND e.worker_id = ?'; params.push(Number(worker)); }
    if (jobsite) { sql += ' AND e.jobsite_id = ?'; params.push(Number(jobsite)); }
    if (task)    { sql += ' AND e.task_id = ?'; params.push(Number(task)); }
    sql += ' ORDER BY e.clock_in DESC LIMIT 2000';
    const { results } = await env.HADFIELD_DB.prepare(sql).bind(...params).all();
    return json({ entries: results });
  }

  if (method === 'POST') {
    // Admin adds a missing punch
    const body = await req.json().catch(() => ({}));
    const { worker_id, jobsite_id, task_id, clock_in, clock_out, notes } = body;
    if (!worker_id || !clock_in) return err(400, 'worker_id and clock_in required');
    const now = Date.now();
    const res = await env.HADFIELD_DB.prepare(
      `INSERT INTO time_entries
         (worker_id, jobsite_id, task_id, clock_in, clock_out, notes, edited_by_admin, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 1, ?)`
    ).bind(
      Number(worker_id),
      jobsite_id ? Number(jobsite_id) : null,
      task_id ? Number(task_id) : null,
      Number(clock_in),
      clock_out ? Number(clock_out) : null,
      notes || null,
      now,
    ).run();
    const entryId = res.meta.last_row_id;
    await env.HADFIELD_DB.prepare(
      'INSERT INTO entry_audit (entry_id, admin_email, action, after_json, changed_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(entryId, a.email, 'created', JSON.stringify(body), now).run();
    return json({ id: entryId });
  }
  return err(405, 'Method not allowed');
}

async function adminEntryOne(req, env, id, method) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);

  const before = await env.HADFIELD_DB.prepare('SELECT * FROM time_entries WHERE id = ?').bind(id).first();
  if (!before) return err(404, 'Entry not found');

  if (method === 'PATCH') {
    const body = await req.json().catch(() => ({}));
    const sets = [], vals = [];
    for (const k of ['worker_id', 'jobsite_id', 'task_id', 'clock_in', 'clock_out', 'notes']) {
      if (body[k] !== undefined) {
        sets.push(`${k} = ?`);
        vals.push(body[k] === null || body[k] === '' ? null : (k === 'notes' ? String(body[k]) : Number(body[k])));
      }
    }
    if (!sets.length) return err(400, 'No fields to update');
    sets.push('edited_by_admin = 1');
    vals.push(id);
    await env.HADFIELD_DB.prepare(`UPDATE time_entries SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
    const after = await env.HADFIELD_DB.prepare('SELECT * FROM time_entries WHERE id = ?').bind(id).first();
    await env.HADFIELD_DB.prepare(
      'INSERT INTO entry_audit (entry_id, admin_email, action, before_json, after_json, changed_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(id, a.email, 'edited', JSON.stringify(before), JSON.stringify(after), Date.now()).run();
    return json({ ok: true });
  }

  if (method === 'DELETE') {
    await env.HADFIELD_DB.prepare('DELETE FROM time_entries WHERE id = ?').bind(id).run();
    await env.HADFIELD_DB.prepare(
      'INSERT INTO entry_audit (entry_id, admin_email, action, before_json, changed_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(id, a.email, 'deleted', JSON.stringify(before), Date.now()).run();
    return json({ ok: true });
  }
  return err(405, 'Method not allowed');
}

async function adminEntryAudit(req, env, id) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);
  const { results } = await env.HADFIELD_DB.prepare(
    'SELECT * FROM entry_audit WHERE entry_id = ? ORDER BY changed_at DESC'
  ).bind(id).all();
  return json({ audit: results });
}

// ---- CSV export (QuickBooks-friendly) ----

function csvEscape(v) {
  if (v == null) return '';
  const s = String(v);
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

async function adminExportCsv(req, env) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);
  const u = new URL(req.url);
  const from = Number(u.searchParams.get('from') || 0);
  const to   = Number(u.searchParams.get('to') || Date.now());
  const tz   = u.searchParams.get('tz') || 'America/Los_Angeles';

  const { results } = await env.HADFIELD_DB.prepare(
    `SELECT e.*,
            w.full_name AS worker_name,
            w.qb_employee_id,
            j.name AS jobsite_name,
            t.name AS task_name,
            t.qb_service_item
       FROM time_entries e
       JOIN workers w  ON w.id = e.worker_id
       LEFT JOIN jobsites j ON j.id = e.jobsite_id
       LEFT JOIN tasks t    ON t.id = e.task_id
      WHERE e.clock_in >= ? AND e.clock_in <= ? AND e.clock_out IS NOT NULL
      ORDER BY e.clock_in ASC`
  ).bind(from, to).all();

  const fmt = new Intl.DateTimeFormat('en-CA', {
    timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit',
  });

  const rows = [[
    'employee_name', 'qb_employee_id', 'date', 'jobsite', 'service_item',
    'clock_in_iso', 'clock_out_iso', 'hours', 'notes',
  ]];
  for (const r of results) {
    const hours = ((r.clock_out - r.clock_in) / 3600000).toFixed(2);
    rows.push([
      r.worker_name,
      r.qb_employee_id || '',
      fmt.format(new Date(r.clock_in)),
      r.jobsite_name || '',
      r.qb_service_item || r.task_name || '',
      new Date(r.clock_in).toISOString(),
      r.clock_out ? new Date(r.clock_out).toISOString() : '',
      hours,
      r.notes || '',
    ]);
  }
  const csv = rows.map(r => r.map(csvEscape).join(',')).join('\n');
  const filename = `hadfield-timesheet-${new Date(from).toISOString().slice(0, 10)}-to-${new Date(to).toISOString().slice(0, 10)}.csv`;
  return new Response(csv, {
    status: 200,
    headers: {
      'content-type': 'text/csv; charset=utf-8',
      'content-disposition': `attachment; filename="${filename}"`,
      'cache-control': 'no-store',
    },
  });
}

// ---- Settings ----

async function adminSettings(req, env, method) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);
  if (method === 'GET') {
    const { results } = await env.HADFIELD_DB.prepare('SELECT key, value FROM settings').all();
    const out = {};
    for (const r of results) out[r.key] = r.value;
    return json({ settings: out });
  }
  if (method === 'PATCH') {
    const body = await req.json().catch(() => ({}));
    const entries = Object.entries(body || {});
    for (const [k, v] of entries) {
      await env.HADFIELD_DB.prepare(
        'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
      ).bind(k, String(v)).run();
    }
    return json({ ok: true, updated: entries.length });
  }
  return err(405, 'Method not allowed');
}

// ─── Billing route handlers ──────────────────────────────────────────────────
// All /api/billing/* handlers go through requireAdmin — the admin signed in via
// CF Access is the only human who can trigger Stripe operations.
// The webhook endpoint (/api/stripe/webhook) is NOT admin-guarded — Stripe's
// servers can't carry a CF Access JWT, so it relies on HMAC signature
// verification in code instead.

async function billingStatus(req, env) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);
  const state = await getBillingState(env);
  // Also return the Stripe publishable key so the admin frontend can init
  // Stripe.js with a single fetch. Publishable key is safe to expose.
  return json({ state, publishable_key: env.STRIPE_PUBLISHABLE_KEY || null });
}

// Create (or fetch) the Stripe Customer for Hadfield Properties LLC, then
// create a SetupIntent the frontend will use to collect the card.
async function billingSetupIntent(req, env) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);

  try {
    let state = await getBillingState(env);
    if (!state.customer_id) {
      const cust = await stripeApi(env, 'POST', '/v1/customers', {
        name: 'Hadfield Properties LLC',
        email: a.email,
        description: 'Apps For Hire — Family Tier subscription',
        metadata: { platform: 'appsforhire', account: 'hadfield' },
      });
      state = await setBillingState(env, { customer_id: cust.id });
    }

    const si = await stripeApi(env, 'POST', '/v1/setup_intents', {
      customer: state.customer_id,
      payment_method_types: ['card'],
      usage: 'off_session',
    });

    return json({ client_secret: si.client_secret, customer_id: state.customer_id });
  } catch (e) {
    return err(e.status || 500, e.message);
  }
}

// After the frontend confirms the SetupIntent, it sends us the resulting
// payment_method ID. We attach it, make it the default, then either update
// the existing subscription or create a brand new one against STRIPE_PRICE_FAMILY.
async function billingConfirmSubscription(req, env) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);
  if (!env.STRIPE_PRICE_FAMILY) return err(500, 'STRIPE_PRICE_FAMILY not configured');

  const body = await req.json().catch(() => ({}));
  const { payment_method_id } = body;
  if (!payment_method_id) return err(400, 'payment_method_id required');

  try {
    const state = await getBillingState(env);
    if (!state.customer_id) return err(400, 'No Stripe customer yet — call /setup-intent first');

    await stripeApi(env, 'POST', `/v1/payment_methods/${encodeURIComponent(payment_method_id)}/attach`, {
      customer: state.customer_id,
    });
    await stripeApi(env, 'POST', `/v1/customers/${encodeURIComponent(state.customer_id)}`, {
      invoice_settings: { default_payment_method: payment_method_id },
    });

    // Already subscribed? Just update default payment method on the sub.
    if (state.subscription_id && ['active', 'past_due', 'trialing', 'unpaid'].includes(state.status)) {
      const sub = await stripeApi(env, 'POST', `/v1/subscriptions/${encodeURIComponent(state.subscription_id)}`, {
        default_payment_method: payment_method_id,
        cancel_at_period_end: 'false',  // re-activating resets any scheduled cancel
      });
      const next = await setBillingState(env, {
        status: sub.status,
        current_period_end: sub.current_period_end,
        cancel_at_period_end: !!sub.cancel_at_period_end,
      });
      return json({ state: next, reactivated: true });
    }

    // New subscription.
    const sub = await stripeApi(env, 'POST', '/v1/subscriptions', {
      customer: state.customer_id,
      items: [{ price: env.STRIPE_PRICE_FAMILY }],
      default_payment_method: payment_method_id,
      metadata: { platform: 'appsforhire', account: 'hadfield' },
    });

    const next = await setBillingState(env, {
      subscription_id: sub.id,
      status: sub.status,
      current_period_end: sub.current_period_end,
      cancel_at_period_end: !!sub.cancel_at_period_end,
    });
    return json({ state: next, subscribed: true });
  } catch (e) {
    return err(e.status || 500, e.message);
  }
}

// Update card = reuse the setup-intent flow. Frontend collects a new card and
// calls /confirm-subscription again, which attaches + sets default.
async function billingUpdateCard(req, env) {
  return billingSetupIntent(req, env);
}

async function billingCancel(req, env) {
  const a = await requireAdmin(req, env);
  if (!a.ok) return err(a.status, a.msg);

  try {
    const state = await getBillingState(env);
    if (!state.subscription_id) return err(400, 'No active subscription');

    // cancel_at_period_end keeps service live through what they already paid for.
    const sub = await stripeApi(env, 'POST', `/v1/subscriptions/${encodeURIComponent(state.subscription_id)}`, {
      cancel_at_period_end: 'true',
    });
    const next = await setBillingState(env, {
      status: sub.status,
      current_period_end: sub.current_period_end,
      cancel_at_period_end: !!sub.cancel_at_period_end,
    });
    return json({ state: next });
  } catch (e) {
    return err(e.status || 500, e.message);
  }
}

// Stripe webhook endpoint. No CF Access. Signature-verified.
async function stripeWebhook(req, env) {
  if (!env.STRIPE_WEBHOOK_SECRET) return err(500, 'STRIPE_WEBHOOK_SECRET not configured');
  const sig = req.headers.get('stripe-signature');
  if (!sig) return err(400, 'Missing stripe-signature header');

  const raw = await req.text();
  const valid = await verifyStripeSignature(raw, sig, env.STRIPE_WEBHOOK_SECRET);
  if (!valid) return err(401, 'Signature verification failed');

  let event;
  try { event = JSON.parse(raw); }
  catch { return err(400, 'Invalid JSON in webhook body'); }

  console.log(`[stripe] event: ${event.type} (${event.id})`);

  try {
    switch (event.type) {
      case 'customer.subscription.created':
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        await setBillingState(env, {
          subscription_id: sub.id,
          status: sub.status,
          current_period_end: sub.current_period_end,
          cancel_at_period_end: !!sub.cancel_at_period_end,
        });
        break;
      }
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        await setBillingState(env, {
          status: 'canceled',
          subscription_id: sub.id,
          current_period_end: sub.current_period_end,
          cancel_at_period_end: false,
        });
        break;
      }
      case 'invoice.payment_succeeded': {
        const inv = event.data.object;
        const periodEnd = inv.lines?.data?.[0]?.period?.end || null;
        await setBillingState(env, {
          last_invoice_id: inv.id,
          status: 'active',
          ...(periodEnd ? { current_period_end: periodEnd } : {}),
        });
        break;
      }
      case 'invoice.payment_failed': {
        const inv = event.data.object;
        await setBillingState(env, {
          last_invoice_id: inv.id,
          status: 'past_due',
        });
        break;
      }
      default:
        // Acknowledged-but-ignored — Stripe wants a 2xx so it stops retrying.
        break;
    }
  } catch (e) {
    console.log(`[stripe] handler error for ${event.type}: ${e.message}`);
    return err(500, 'Webhook handler failed');
  }

  return json({ received: true });
}

// ─── Main router ─────────────────────────────────────────────────────────────

export default {
  async fetch(req, env) {
    try {
      const url = new URL(req.url);
      const p = url.pathname;
      const m = req.method;

      // Health
      if (p === '/health' || p === '/api/health') return handleHealth(env);

      // Worker routes
      if (p === '/api/worker/workers'    && m === 'GET')  return listActiveWorkers(env);
      if (p === '/api/worker/verify-pin' && m === 'POST') return verifyPin(req, env);
      if (p === '/api/worker/logout'     && m === 'POST') return workerLogout();
      if (p === '/api/worker/context'    && m === 'GET')  return workerContext(req, env);
      if (p === '/api/worker/status'     && m === 'GET')  return workerStatus(req, env);
      if (p === '/api/worker/clock-in'   && m === 'POST') return workerClockIn(req, env);
      if (p === '/api/worker/clock-out'  && m === 'POST') return workerClockOut(req, env);

      // Admin routes
      if (p === '/api/admin/whoami'      && m === 'GET')  return adminWhoami(req, env);
      if (p === '/api/admin/dashboard'   && m === 'GET')  return adminDashboard(req, env);

      if (p === '/api/admin/workers')                      return adminWorkers(req, env, m);
      let mm = p.match(/^\/api\/admin\/workers\/(\d+)$/);
      if (mm)                                              return adminWorkerOne(req, env, Number(mm[1]), m);

      if (p === '/api/admin/jobsites')                     return adminJobsites(req, env, m);
      mm = p.match(/^\/api\/admin\/jobsites\/(\d+)$/);
      if (mm)                                              return adminJobsiteOne(req, env, Number(mm[1]), m);

      if (p === '/api/admin/tasks')                        return adminTasks(req, env, m);
      mm = p.match(/^\/api\/admin\/tasks\/(\d+)$/);
      if (mm)                                              return adminTaskOne(req, env, Number(mm[1]), m);

      if (p === '/api/admin/entries')                      return adminEntries(req, env, m);
      mm = p.match(/^\/api\/admin\/entries\/(\d+)\/audit$/);
      if (mm && m === 'GET')                               return adminEntryAudit(req, env, Number(mm[1]));
      mm = p.match(/^\/api\/admin\/entries\/(\d+)$/);
      if (mm)                                              return adminEntryOne(req, env, Number(mm[1]), m);

      if (p === '/api/admin/export/csv'  && m === 'GET')   return adminExportCsv(req, env);
      if (p === '/api/admin/settings')                     return adminSettings(req, env, m);

      // Billing routes (admin-guarded)
      if (p === '/api/billing/status'               && m === 'GET')  return billingStatus(req, env);
      if (p === '/api/billing/setup-intent'         && m === 'POST') return billingSetupIntent(req, env);
      if (p === '/api/billing/confirm-subscription' && m === 'POST') return billingConfirmSubscription(req, env);
      if (p === '/api/billing/update-card'          && m === 'POST') return billingUpdateCard(req, env);
      if (p === '/api/billing/cancel'               && m === 'POST') return billingCancel(req, env);

      // Stripe webhook — NOT CF-Access-protected. Verified in code.
      if (p === '/api/stripe/webhook'               && m === 'POST') return stripeWebhook(req, env);

      return err(404, `No route for ${m} ${p}`);
    } catch (e) {
      return err(500, `Server error: ${e.message || e}`);
    }
  },
};
