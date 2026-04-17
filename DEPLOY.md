# Hadfield Time Tracker — deploy guide

Two moving parts: the **Worker** (`hadfield-worker`, the API backend) and the
**frontend** (`app/`, `admin/`, `index.html`, pushed to the
`client-hadfieldproperties` GitHub Pages repo).

---

## First-time Cloudflare setup (one-time)

Run these once, **in this exact order**. Some commands depend on values produced
by earlier steps (that's why order matters — the secret for `CF_ACCESS_AUD`
can't be set before the CF Access app exists).

### Step 1 — DNS (so the hostname resolves)

In the Cloudflare dashboard for the `appsforhire.app` zone:

- Add a **CNAME** record
  - **Name:** `hadfieldproperties`
  - **Target:** `cosmicwombat.github.io`
  - **Proxy status:** Proxied (orange cloud) — required for CF Access to sit in front

### Step 2 — Cloudflare infrastructure (D1, KV, R2, migrations)

```bash
cd ~/app_for_hire/builds/hadfieldproperties/worker

# D1 database
npx wrangler d1 create hadfield-db
# → copy database_id into wrangler.toml

# KV namespace
npx wrangler kv namespace create hadfield-kv
# → copy id into wrangler.toml

# R2 bucket
npx wrangler r2 bucket create hadfield-assets

# Apply the schema
npx wrangler d1 execute hadfield-db --remote --file=./migrations/0001_initial.sql
```

### Step 3 — Create the Cloudflare Access application

In the Cloudflare dashboard:

1. **Zero Trust** → **Access** → **Applications** → **Add an application**
2. Choose **Self-hosted and private** → **Continue**
3. Configure:
   - **Application name:** `Hadfield Admin`
   - **Session duration:** `24 hours`
   - **Public hostname:**
     - Subdomain: `hadfieldproperties`
     - Domain: `appsforhire.app`
     - Path: `admin/*`
   - **Identity providers:** uncheck "Accept all available identity providers", select only **One-time PIN**
4. **Policy:** either reuse your account-level admin policy, or create a new one:
   - Action: `Allow`, Include: `Emails` → `cosmicwombat@gmail.com`
   - Require: `One-time PIN`
5. Save the app.
6. Open the new app → **Overview** tab → copy the **Application Audience (AUD) Tag**

### Step 4 — Set Worker secrets

```bash
cd ~/app_for_hire/builds/hadfieldproperties/worker

npx wrangler secret put WORKER_SESSION_SECRET --name hadfield-worker
# paste output of: openssl rand -hex 32

npx wrangler secret put CF_ACCESS_AUD --name hadfield-worker
# paste the AUD tag from Step 3

npx wrangler secret put CF_ACCESS_TEAM --name hadfield-worker
# e.g. cosmicwombat.cloudflareaccess.com  (no https://, no trailing slash)
# Find this in Zero Trust → Settings → Custom Pages (shown at the top)

npx wrangler secret put ADMIN_EMAILS --name hadfield-worker
# e.g. cosmicwombat@gmail.com
# (comma-separated if multiple — this is an allowlist belt-and-suspenders on top of CF Access)
```

### Step 5 — Deploy the Worker

```bash
npx wrangler deploy --name hadfield-worker
```

Per memory `feedback_redeploy_after_secrets`, the Worker must be redeployed
after any `wrangler secret put` so it picks up the new secrets.

### Step 6 — Deploy the frontend (GitHub Pages)

```bash
cd ~/app_for_hire
python3 scripts/deploy_app.py hadfieldproperties
```

This pushes `app/`, `admin/`, `index.html`, `manifest.json`, `sw.js` to the
`client-hadfieldproperties` repo → GitHub Pages → `https://hadfieldproperties.appsforhire.app`.

---

## Re-deploys (ongoing)

### Frontend only

```bash
cd ~/app_for_hire
python3 scripts/deploy_app.py hadfieldproperties
```

### Worker only (after any `worker.js`, `wrangler.toml`, or secret change)

```bash
cd ~/app_for_hire/builds/hadfieldproperties/worker
npx wrangler deploy --name hadfield-worker
```

---

## Smoke-test checklist

1. `https://hadfieldproperties.appsforhire.app/health` → JSON, all bindings and secrets `true`, `ok: true`
2. `https://hadfieldproperties.appsforhire.app/admin/` → CF Access prompts OTP; after you authenticate you see the Admin dashboard
3. Admin → **Workers** → **+ Add worker** → create a test worker (remember the 4-digit PIN it shows)
4. `https://hadfieldproperties.appsforhire.app/app/` on a phone → pick the test worker → enter PIN → pick Mill Creek + Framing → tap **CLOCK IN**
5. Admin Dashboard → test worker shows in "Currently clocked in"
6. On phone: wait a few seconds (UI auto-returns to the name screen), pick name + PIN again, tap **CLOCK OUT**
7. Admin → **Time entries** → verify the entry is there with clock-in and clock-out times
8. Admin → **Reports** → generate a test PDF and download a CSV

---

## Common errors

| Error | Fix |
|---|---|
| `401 Invalid CF Access token` on admin | `CF_ACCESS_AUD` or `CF_ACCESS_TEAM` is wrong. Team domain must have no `https://` prefix. Redeploy the Worker after fixing. |
| `401 No CF Access token` on admin | CF Access isn't in front of `/admin/*`. Check the Access app's hostname + path are exactly `hadfieldproperties.appsforhire.app/admin/*`. |
| `401 Session expired` on worker app | PIN session is 12h. Worker needs to pick their name and re-enter their PIN. |
| `500 D1_ERROR` on any call | Migrations not applied. Run `npx wrangler d1 execute hadfield-db --remote --file=./migrations/0001_initial.sql`. |
| Admin panel shows `PDFLib is not defined` when generating a PDF | The pdf-lib CDN failed to load. Hard-refresh the page. |
| `/health` returns any `false` under `secrets` | That secret wasn't set. Re-run `wrangler secret put` then `wrangler deploy`. |
