# Mortar & Pestle SAT — v2

DSAT Reading & Writing practice bank. Static front end (`index.html`) plus **one**
serverless function (`api/store.js`) backed by Vercel Blob.

---

## Deploying

### 1. Connect the Blob store

Vercel dashboard → your project → **Storage** → connect **`digitalsatpestl-blob`**.

That injects `BLOB_READ_WRITE_TOKEN` automatically. Nothing else is required — if the
variable is missing the API returns a clear error rather than failing silently.

### 2. Optional: set a signing secret

**Settings → Environment Variables**

| Name | Value |
|---|---|
| `MP_SECRET` | any long random string |

If unset it is derived from the blob token, which works fine. Setting it explicitly means
session cookies and blob path hashes survive a blob-token rotation.

### 3. Push and deploy

```bash
git add -A
git commit -m "v2: accounts, quick practice, pause, notes, admin, guide"
git push
```

Vercel installs `@vercel/blob` from `package.json` and deploys. No build step.

---

## Why this does not need Vercel Pro

| Pro-only thing | Used here |
|---|---|
| >12 serverless functions | **1** function total |
| Cron jobs | none |
| Edge Config / Middleware | none |
| ISR / on-demand revalidation | none |
| Image Optimization | none — images are plain static files |

Hobby limits that matter: 100 GB bandwidth/month and 1 M function invocations. Syncs are
debounced to one write per 1.5 s of activity, so a heavy user costs a few hundred
invocations a day.

---

## Access control

- **Master key: `ma00dc9`.** Logging in with the account bound to this token reveals the
  **Admin** tab. Every admin operation is re-checked server-side; hiding the tab is
  cosmetic, not the security boundary.
- **Tokens are single-use and browser-bound.** The first browser to redeem a token is
  bound to it permanently, server-side. Clearing the cache does *not* release it.
- **Accounts are the portable half.** Once created, log in anywhere. Passwords are
  PBKDF2-SHA256, 60 000 iterations, per-account salt.
- **Revocation is immediate.** Revoking a token or account blocks the next request of any
  kind — login, sync, or admin.

Seed tokens are in `SEED_TOKENS` in `api/store.js`; after first contact the blob store is
the source of truth and everything is managed from the Admin page.

### Admin operations

Issue token · Revoke / Restore token · Unbind token from its browser · Delete token ·
Revoke / Restore account · Reset a user's password · Delete account and all its data.

---

## Data model

Blob pathnames are HMAC'd with the secret, so although Vercel Blob objects are public-by-URL,
none of them are guessable.

| Prefix | Contents |
|---|---|
| `tk/` | token record — binding, revocation, owning account |
| `ac/` | account — username, name, salt, password hash |
| `dt/` | full progress snapshot for one account |

The client keeps working from `localStorage` and syncs the whole snapshot up. On login,
local and cloud are **union-merged** by record ID, so a browser holding unsynced work never
loses it to the cloud copy, or vice versa.

---

## Existing users

On first load after this update, anyone with local progress and no account is sent
straight to the signup form with their old token pre-filled. Their entire local snapshot —
attempts, sessions, collections, notes, vocab — is uploaded as the account's starting
state. Nothing is discarded.

---

## Local development

```bash
npm i -g vercel
vercel dev
```

`vercel dev` pulls the blob token from the linked project. Without it, the front end still
runs and falls back to local-only mode with the sync chip reading `offline`.
