# Hadfield Properties — Billing Setup

This is the runbook for wiring up Stripe billing on the Hadfield worker.
We bill Hadfield $15/mo for the Apps For Hire "Family" tier.

Do it once in **TEST mode** end-to-end (Phase 10B → 10D below).
Then flip to **LIVE mode** and onboard Robert's real card (Phase 10E).

> All commands use full paths. Run them in **Terminal.app**, one at a time.
> Wherever you see `cd ~/apps_for_hire/builds/hadfieldproperties/worker`,
> copy-paste the whole command — don't retype it.

---

## Architecture summary

```
Admin (Robert) ──► /admin/billing.html  (CF-Access-protected)
                        │
                        ▼
                 hadfield-worker
                  /api/billing/*       ◄── CF-Access-guarded (requireAdmin)
                  /api/stripe/webhook  ◄── NOT CF-Access-guarded
                                           (verified by HMAC signature)
                        │
                        ▼
                     Stripe API

State:  HADFIELD_KV key "billing:state" (one JSON blob)
```

---

## Phase 10B — Stripe dashboard setup (TEST mode)

Log into <https://dashboard.stripe.com> as Robert (`cosmicwombat@gmail.com`
or whatever the Apps For Hire Stripe account is). **Flip the toggle in the
top-right to "Test mode" — everything below is in test mode.**

### 1. Create the product + price

1. Open **Product catalog** → **Add product**.
2. Name: `Apps For Hire — Family Tier`
3. Description: `Hosting + updates for family & friends apps ($15/mo)`
4. Pricing:
   - **Recurring**
   - **$15.00 USD**
   - **Monthly**
   - Tax behavior: `Exclusive` (default — we're not collecting sales tax)
5. Click **Save product**.
6. On the product page, find the **Price ID** — it looks like `price_1AbCdEfGhIjKlMnO`.
   **Copy it.** You'll paste it into `STRIPE_PRICE_FAMILY` below.

### 2. Get your API keys

1. Open **Developers** → **API keys**.
2. Copy these two values:
   - **Publishable key** — starts with `pk_test_` — goes into `STRIPE_PUBLISHABLE_KEY`
   - **Secret key** — starts with `sk_test_` — goes into `STRIPE_SECRET_KEY`
3. ⚠️ The Secret key is only shown once. Store it somewhere safe (your keychain app, or `~/keys/`).

### 3. Register the webhook endpoint

1. Open **Developers** → **Webhooks** → **Add endpoint**.
2. Endpoint URL: `https://hadfieldproperties.appsforhire.app/api/stripe/webhook`
3. Events to send — click **Select events** and check:
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
4. Click **Add endpoint**.
5. On the endpoint page, click **Reveal signing secret**.
   It starts with `whsec_…`. Copy it. Goes into `STRIPE_WEBHOOK_SECRET`.

---

## Phase 10C — Set secrets + deploy worker

You now have four values:

| Env var name            | Example prefix         | Where it came from |
| ----------------------- | ---------------------- | ------------------ |
| `STRIPE_SECRET_KEY`     | `sk_test_…`            | API keys page      |
| `STRIPE_PUBLISHABLE_KEY`| `pk_test_…`            | API keys page      |
| `STRIPE_PRICE_FAMILY`   | `price_…`              | Product catalog    |
| `STRIPE_WEBHOOK_SECRET` | `whsec_…`              | Webhook endpoint   |

Open Terminal.app and run each `wrangler secret put` — it will prompt you,
paste the value, press Enter.

```bash
cd /Users/rkeller/apps_for_hire/builds/hadfieldproperties/worker
npx wrangler@3 secret put STRIPE_SECRET_KEY --name hadfield-worker
```
*(Paste `sk_test_...` when prompted, press Enter.)*

```bash
cd /Users/rkeller/apps_for_hire/builds/hadfieldproperties/worker
npx wrangler@3 secret put STRIPE_PUBLISHABLE_KEY --name hadfield-worker
```

```bash
cd /Users/rkeller/apps_for_hire/builds/hadfieldproperties/worker
npx wrangler@3 secret put STRIPE_PRICE_FAMILY --name hadfield-worker
```

```bash
cd /Users/rkeller/apps_for_hire/builds/hadfieldproperties/worker
npx wrangler@3 secret put STRIPE_WEBHOOK_SECRET --name hadfield-worker
```

### Deploy the new worker code

```bash
cd /Users/rkeller/apps_for_hire/builds/hadfieldproperties/worker
npx wrangler@3 deploy --name hadfield-worker
```

Expected output: "Uploaded hadfield-worker (N sec)" + "Deployed hadfield-worker
triggers: hadfieldproperties.appsforhire.app/* (N sec)".

### Deploy billing.html (it's part of the admin static site)

How static assets get served depends on how `admin/` is hosted today.
Check with:

```bash
ls -la /Users/rkeller/apps_for_hire/builds/hadfieldproperties/admin/
```

If it's served via Cloudflare Pages (project `hadfield-admin` or similar),
push to main — Pages redeploys on commit. If it's bundled into the worker,
the `wrangler deploy` above already shipped it. If it's on GitHub Pages,
`git push` to the configured branch.

### Verify CF Access rules

⚠️ **Important:** the Stripe webhook at `/api/stripe/webhook` must NOT be
behind CF Access — Stripe's servers can't carry a CF Access JWT.

1. Cloudflare dashboard → **Zero Trust** → **Access** → **Applications**.
2. Find the app that protects `hadfieldproperties.appsforhire.app`.
3. Its path pattern should be `/admin/*` and `/api/admin/*` — not `/*`.
4. If the whole domain is protected, edit the application and narrow the
   path patterns. Test with:

```bash
curl -i https://hadfieldproperties.appsforhire.app/api/stripe/webhook -d '{}'
```

Expected: **400 Missing stripe-signature header** (not a CF Access login page).

### Verify health endpoint sees the secrets

```bash
curl -s https://hadfieldproperties.appsforhire.app/health | python3 -m json.tool
```

In the `secrets` block you should see:

```
"STRIPE_SECRET_KEY": true,
"STRIPE_PUBLISHABLE_KEY": true,
"STRIPE_PRICE_FAMILY": true,
"STRIPE_WEBHOOK_SECRET": true,
```

If any is `false` — re-run the corresponding `wrangler secret put` above,
then redeploy with `wrangler deploy --name hadfield-worker`.

---

## Phase 10D — End-to-end test (still in TEST mode)

1. Open <https://hadfieldproperties.appsforhire.app/admin/billing.html>
2. Sign in via CF Access if prompted.
3. You should see the 🧪 TEST MODE banner and "Subscribe to the Family tier".
4. Click **Add payment method**.
5. Card details:
   - Number: `4242 4242 4242 4242`
   - Expiry: any future date (e.g. `12/30`)
   - CVC: any 3 digits (e.g. `123`)
   - ZIP: any (e.g. `98225`)
6. Click **Subscribe — $15.00 / mo**.
7. Expected: toast "Subscription started", panel flips to **active**,
   you see Customer ID, Subscription ID, next renewal date.

### Verify in Stripe dashboard

- **Customers** → should show `Hadfield Properties LLC`
- **Subscriptions** → should show one active, $15/mo
- **Webhooks** → click your endpoint → **Events** tab → should see
  `customer.subscription.created` and `invoice.payment_succeeded`
  with 200 responses.

### Verify in worker KV

Cloudflare dashboard → **Workers & Pages** → **KV** → `HADFIELD_KV` →
key `billing:state`. Value should be valid JSON with:

```json
{
  "customer_id":        "cus_…",
  "subscription_id":    "sub_…",
  "status":             "active",
  "current_period_end": 176…,
  "cancel_at_period_end": false,
  "last_invoice_id":    "in_…",
  "updated_at":         "2026-04-21T…Z"
}
```

### Test cancel + resubscribe

1. On billing.html click **Cancel subscription**.
2. Confirm the dialog.
3. Expected: pill still says `active` but next-renewal line changes to
   "Cancels on …".
4. Refresh. Click **Resubscribe**? No — while `cancel_at_period_end=true`
   the subscription is still active, you stay in the active panel.
   Click **Update card** and re-confirm — that resets cancel-at-period-end
   back to false.

### Test failed card (optional)

Card `4000 0000 0000 0002` is declined on create. Card
`4000 0000 0000 9995` succeeds on create but fails on first invoice.
Use either in the Subscribe flow to verify error handling.

---

## Phase 10E — Flip to LIVE mode

⚠️ **Only do this once Phase 10D is green.** Live-mode charges real money.

1. Stripe dashboard → toggle **Test mode** OFF (top-right).
2. Repeat Phase 10B (create the live Product + Price, live webhook) — you'll
   get new live-mode IDs. Live-mode keys start with `sk_live_`, `pk_live_`,
   `price_` (no prefix change), `whsec_` (no prefix change).
3. Re-run the four `wrangler secret put` commands above with live values:

```bash
cd /Users/rkeller/apps_for_hire/builds/hadfieldproperties/worker
npx wrangler@3 secret put STRIPE_SECRET_KEY --name hadfield-worker
# paste sk_live_…

npx wrangler@3 secret put STRIPE_PUBLISHABLE_KEY --name hadfield-worker
# paste pk_live_…

npx wrangler@3 secret put STRIPE_PRICE_FAMILY --name hadfield-worker
# paste live price_…

npx wrangler@3 secret put STRIPE_WEBHOOK_SECRET --name hadfield-worker
# paste live whsec_…
```

4. Redeploy:

```bash
cd /Users/rkeller/apps_for_hire/builds/hadfieldproperties/worker
npx wrangler@3 deploy --name hadfield-worker
```

5. Open billing.html — TEST MODE banner should be gone.
6. Subscribe with Robert's real Visa.
7. Verify in Stripe dashboard (live mode): Customer, Subscription, successful
   invoice. Verify in KV: `status: "active"`.
8. Done. Robert pays $15/mo; you're making money on Apps For Hire.

---

## Troubleshooting

**"Billing not configured" panel shows up.**
→ `STRIPE_PUBLISHABLE_KEY` secret isn't set. Re-run step 3 of Phase 10C.

**Card setup fails with "Your card was declined."**
→ In TEST mode, only `4242 4242 4242 4242` succeeds. Other test numbers are
intentionally designed to fail.

**Webhook dashboard shows 401 "Signature verification failed".**
→ `STRIPE_WEBHOOK_SECRET` doesn't match the endpoint. On the webhook
endpoint page, click **Roll signing secret**, copy the new `whsec_…`,
re-run `wrangler secret put STRIPE_WEBHOOK_SECRET` and redeploy.

**Webhook dashboard shows 403 "Forbidden" from CF Access.**
→ CF Access is still protecting `/api/stripe/*`. See "Verify CF Access
rules" in Phase 10C.

**Subscribe button does nothing.**
→ Open browser devtools → Console. Probably a Stripe.js error. Usually
means `STRIPE_PUBLISHABLE_KEY` is wrong (test key while in live mode or
vice versa).

**"No Stripe customer yet — call /setup-intent first"**
→ Someone called `/confirm-subscription` before `/setup-intent` completed.
Click **Back** and start over.

---

## Files involved

- `builds/hadfieldproperties/worker/worker.js` — billing + webhook handlers
- `builds/hadfieldproperties/admin/billing.html` — admin billing UI
- `builds/hadfieldproperties/BILLING_SETUP.md` — this file

## What gets backed up

`HADFIELD_KV` (which includes `billing:state`) is backed up nightly by
`.github/workflows/backup.yml` → `afh-backups/hadfield/kv/<date>/HADFIELD_KV.json`.
30-day retention via the `auto-expire-30d` R2 lifecycle rule.

Stripe is itself the source-of-truth for customer/subscription/payment data —
we just mirror the current state into KV for fast lookups. If the KV entry
were lost, it could be rebuilt by re-querying Stripe for the customer's
active subscription.
