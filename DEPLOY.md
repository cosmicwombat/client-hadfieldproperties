# Hadfield Time Tracker — deploy guide

Two moving parts:

- **Worker** (`hadfield-worker`) — the API backend on Cloudflare Workers
- **Frontend** (`app/`, `admin/`, `index.html`, `manifest.json`, `sw.js`) — pushed to the `client-hadfieldproperties` GitHub Pages repo, served via `hadfieldproperties.appsforhire.app`

---

## First-time Cloudflare setup

Run these once, **in this exact order**. Later steps depend on values produced by earlier steps (e.g. `CF_ACCESS_AUD` can't be set until after the CF Access app exists).

### Step 1 — DNS

In the Cloudflare dashboard for the `appsforhire.app` zone, add a CNAME record:

- **Name:** `hadfieldproperties`
- **Target:** `cosmicwombat.github.io`
- **Proxy status:** Proxied (orange cloud) — required so CF Access can sit in front

### Step 2 — Storage + schema

```bash
cd ~/apps_for_hire/builds/hadfieldproperties/worker

# D1 database — copy the printed database_id into wrangler.toml line 20
npx wrangler d1 create hadfield-db

# KV namespace — copy the printed id into wrangler.toml line 25
# (note: Wrangler 3+ uses `kv namespace`, not `kv:namespace`)
npx wrangler kv namespace create hadfield-kv

# R2 bucket
npx wrangler r2 bucket create hadfield-assets

# Apply the initial schema (seeds jobsites + tasks, leaves workers empty)
npx wrangler d1 execute hadfield-db --remote --file=./migrations/0001_initial.sql

# Apply the lunch / self-edit / finish-day schema additions
# SAFE to run on a DB that already has data — uses ALTER TABLE ADD COLUMN
# and only backfills worker_finished_day on rows that are already completed.
# If this errors with "duplicate column name", the migration is already applied.
npx wrangler d1 execute hadfield-db --remote --file=./migrations/0002_lunch.sql
```

### Step 3 — Create the Cloudflare Access application

In the Cloudflare dashboard:

1. **Zero Trust → Access → Applications → Add an application**
2. Choose **Self-hosted and private → Continue**
3. Configure:
   - **Application name:** `Hadfield Admin`
   - **Session duration:** `24 hours`
   - **Public hostname:**
     - Subdomain: `hadfieldproperties`
     - Domain: `appsforhire.app`
     - Path: `admin/*`
   - **Identity providers:** uncheck "Accept all available identity providers", select only **One-time PIN**
4. **Policy:** reuse the account-level admin policy, or create a new one:
   - Action: `Allow`, Include: `Emails → cosmicwombat@gmail.com`
   - Require: `One-time PIN`
5. Save.
6. Open the new app → **Overview** tab → copy the **Application Audience (AUD) Tag** — you'll need it in Step 4.

### Step 4 — Worker secrets

```bash
cd ~/apps_for_hire/builds/hadfieldproperties/worker

# HMAC key for the worker_session cookie (12h PIN login)
npx wrangler secret put WORKER_SESSION_SECRET --name hadfield-worker
# paste: output of `openssl rand -hex 32`

# AUD tag from the CF Access app you just created
npx wrangler secret put CF_ACCESS_AUD --name hadfield-worker
# paste: the Application Audience (AUD) Tag from Step 3

# Zero Trust team domain
npx wrangler secret put CF_ACCESS_TEAM --name hadfield-worker
# paste EXACTLY: appsforhire.cloudflareaccess.com
# (no https://, no trailing slash, no spaces)

# Admin email allowlist (belt-and-suspenders on top of CF Access)
npx wrangler secret put ADMIN_EMAILS --name hadfield-worker
# paste: cosmicwombat@gmail.com
# (comma-separated, no spaces, for multiple:  a@b.com,c@d.com)
```

Before moving on, sanity-check that the team domain serves JSON, not HTML:

```bash
curl -s https://appsforhire.cloudflareaccess.com/cdn-cgi/access/certs | head -c 80
# ✅ good:   {"keys":[{"kid":...
# ❌ wrong:  <!DOCTYPE html>...   → team domain is wrong, do not proceed
```

### Step 5 — Deploy the Worker

```bash
npx wrangler deploy --name hadfield-worker
```

Workers don't pick up new secrets until they're redeployed. Any time you run `wrangler secret put`, you must run `wrangler deploy` again.

### Step 6 — Deploy the frontend

```bash
cd ~/apps_for_hire
python3 scripts/deploy_app.py hadfieldproperties
```

That pushes `app/`, `admin/`, `index.html`, `manifest.json`, and `sw.js` to the `client-hadfieldproperties` GitHub repo → GitHub Pages → `https://hadfieldproperties.appsforhire.app`.

---

## Re-deploys (ongoing)

### Frontend only (edits to `app/`, `admin/`, `index.html`, etc.)

```bash
cd ~/apps_for_hire
python3 scripts/deploy_app.py hadfieldproperties
```

### Worker only (edits to `worker.js`, `wrangler.toml`, or any secret)

```bash
cd ~/apps_for_hire/builds/hadfieldproperties/worker
npx wrangler deploy --name hadfield-worker
```

---

## Upgrade: end-of-day review + self-edit (migration 0002)

This is the one-shot upgrade for an already-live Hadfield deployment that adds
the 4-punch day (clock-in / lunch-out / lunch-in / clock-out), worker self-edit,
and Finish-Day lock. **No existing time entries are lost** — the migration only
adds new columns and marks already-completed rows as "finished".

Run all three commands, in order, from `~/apps_for_hire`:

```bash
# 1. Apply the DB migration (adds columns, builds index, backfills flags).
cd ~/apps_for_hire/builds/hadfieldproperties/worker && \
  npx wrangler d1 execute hadfield-db --remote --file=./migrations/0002_lunch.sql
```

```bash
# 2. Deploy the new Worker code (new /api/worker/lunch-out, lunch-in, today, today/times, today/finish routes).
cd ~/apps_for_hire/builds/hadfieldproperties/worker && \
  npx wrangler deploy --name hadfield-worker
```

```bash
# 3. Deploy the new worker PWA + admin panel (state-driven review screen, lunch columns).
cd ~/apps_for_hire && python3 scripts/deploy_app.py hadfieldproperties
```

If Step 1 errors with `duplicate column name: lunch_out`, the migration is
already applied — skip Step 1 and continue to Step 2. The migration is
idempotent for the backfill (`WHERE worker_finished_day IS NULL`), so the
UPDATE at the bottom is safe to re-run.

---

## Smoke test

1. **Health** — `https://hadfieldproperties.appsforhire.app/health` → JSON with all bindings and secrets `true`, `ok: true`.
2. **Admin auth** — `https://hadfieldproperties.appsforhire.app/admin/` → CF Access prompts for OTP → dashboard loads with no error banner.
3. **Add a worker** — Admin → **Workers** → **+ Add worker** → save. The admin UI shows the new 4-digit PIN once.
4. **Worker clock-in** — On a phone, open `https://hadfieldproperties.appsforhire.app/app/` → pick the test worker → enter PIN → pick Mill Creek + Framing → **CLOCK IN**.
5. **Dashboard** — back on admin, the test worker shows under "Currently clocked in".
6. **Worker clock-out** — on the phone, pick name + PIN again → **CLOCK OUT**.
7. **Entry** — Admin → **Time entries** → the entry is listed with both timestamps.
8. **Reports** — Admin → **Reports** → generate a test PDF and download a CSV.

---

## Common errors

| What you see | What's wrong | Fix |
|---|---|---|
| `/health` returns any `false` under `secrets` | That secret wasn't set | Re-run `wrangler secret put <NAME>` then `wrangler deploy` |
| Admin page 500s with "Worker threw exception" (HTML) | Worker crashed at startup | Check `wrangler tail --name hadfield-worker` for the stack trace |
| `401 Invalid CF Access token: verify threw: Unexpected token '<'` | `CF_ACCESS_TEAM` is wrong — the JWKS URL returned HTML instead of JSON | Reset `CF_ACCESS_TEAM` to `appsforhire.cloudflareaccess.com` and redeploy. Verify with the `curl …/cdn-cgi/access/certs` check above. |
| `401 Invalid CF Access token: aud mismatch` | `CF_ACCESS_AUD` doesn't match the Access app's AUD tag | Copy the AUD tag again from Zero Trust → your app → Overview, reset `CF_ACCESS_AUD`, redeploy |
| `401 No CF Access token` | CF Access isn't in front of `/admin/*` | In the Access app: hostname/path must be exactly `hadfieldproperties.appsforhire.app` + `admin/*` |
| `403 Not in admin allowlist: <email>` | Email isn't in `ADMIN_EMAILS` secret | Re-run `wrangler secret put ADMIN_EMAILS` with a clean comma-separated list, redeploy |
| `401 Session expired` on worker PWA | 12h PIN session timed out | Worker picks their name and re-enters their PIN |
| `500 D1_ERROR` on any API call | Migrations not applied | `npx wrangler d1 execute hadfield-db --remote --file=./migrations/0001_initial.sql` then `./migrations/0002_lunch.sql` |
| Worker PWA: `no such column: lunch_out` in tail logs | Migration `0002_lunch.sql` not yet applied to remote DB | `npx wrangler d1 execute hadfield-db --remote --file=./migrations/0002_lunch.sql` |
| Worker PWA shows "You already have an unfinished day" on a brand-new worker | Pre-migration open row is still in the DB for that worker | Admin panel → Time entries → find the open row for that worker → either set Clock-out + Finish-Day via the ✎ edit, or delete it |
| Admin entries table shows "⚠ lunch" on a row | Only one of `lunch_out` / `lunch_in` is set (worker's phone crashed mid-lunch) | Admin ✎ edit → either fill in the missing punch or clear both lunch fields |
| Admin panel: `PDFLib is not defined` when generating a PDF | pdf-lib CDN failed to load | Hard-refresh the admin page |

---

## Watching logs live

```bash
cd ~/apps_for_hire/builds/hadfieldproperties/worker
npx wrangler tail --name hadfield-worker
```

Then reproduce the issue in the browser — errors stream to your terminal with the exact stack trace.
