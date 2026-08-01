/* ============================================================
   Mortar & Pestle SAT — single backend function
   ------------------------------------------------------------
   ONE serverless function handles every action. Vercel Hobby
   allows 12 functions per deployment; we use 1. No cron jobs,
   no edge config, no ISR — nothing that requires Pro.

   Storage: Vercel Blob ("digitalsatpestl-blob"), PRIVATE access —
   nothing in the store is reachable without the read-write token.
   Env required: BLOB_READ_WRITE_TOKEN  (auto-injected by Vercel
                 when the Blob store is linked to the project)
   Env optional: MP_SECRET  (falls back to a value derived from
                 the blob token, so zero-config still works)

   Blob paths are additionally HMAC'd with the secret, so even a
   leaked store id reveals no account or token pathnames.
   ============================================================ */

import { put, list, del, get } from '@vercel/blob';
import crypto from 'node:crypto';

/* ---------- config ---------- */

const MASTER_TOKEN = 'MA00DC9';

// Seeded on first contact. After that the blob store is the source
// of truth and everything is managed from the in-app Admin page.
const SEED_TOKENS = [
  'MA00DC9', 'GU1DKFGH', 'GU2CNWOA', 'GU3UPNME', 'GU4SPTGUE',
  'GU5SPTGUE', 'GU6DVRGKR', 'GU7EHQJST', 'GU8EHQJST', 'GU9EHQJST'
];

const SESSION_DAYS = 180;

function secret() {
  return process.env.MP_SECRET ||
         ('mp-derived-' + (process.env.BLOB_READ_WRITE_TOKEN || 'local-dev-fallback'));
}

/* ---------- crypto helpers ---------- */

function hmac(s) {
  return crypto.createHmac('sha256', secret()).update(String(s)).digest('hex');
}
function pathFor(kind, key) {
  return kind + '/' + hmac(kind + ':' + String(key).toLowerCase()).slice(0, 40) + '.json';
}
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 60000, 32, 'sha256').toString('hex');
}
function safeEq(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}
function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return body + '.' + crypto.createHmac('sha256', secret()).update(body).digest('base64url');
}
function readSession(sid) {
  if (!sid || typeof sid !== 'string' || sid.indexOf('.') === -1) return null;
  const [body, sig] = sid.split('.');
  const expect = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  if (!safeEq(sig, expect)) return null;
  let p;
  try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch (e) { return null; }
  if (!p || !p.exp || Date.now() > p.exp) return null;
  return p;
}

/* ---------- blob helpers ---------- */

function isNotFound(e) {
  return !!e && (e.name === 'BlobNotFoundError' ||
                 /not.?found|does not exist/i.test(e.message || ''));
}

async function readJSON(pathname) {
  let r;
  try {
    // useCache:false -> always read the latest from origin, never the CDN copy
    r = await get(pathname, { access: 'private', useCache: false });
  } catch (e) {
    if (isNotFound(e)) return null;
    throw e;                       // real failures must surface, not look like "missing"
  }
  if (!r || !r.stream) return null;
  const text = await new Response(r.stream).text();
  try { return JSON.parse(text); } catch (e) { return null; }
}

async function writeJSON(pathname, obj) {
  await put(pathname, JSON.stringify(obj), {
    access: 'private',
    contentType: 'application/json',
    addRandomSuffix: false,
    allowOverwrite: true
    // NOTE: no cacheControlMaxAge — the SDK rejects anything under 60s,
    // and reads already bypass the cache via useCache:false.
  });
  return obj;
}

async function listAll(prefix) {
  const out = [];
  let cursor;
  do {
    const page = await list({ prefix, cursor, limit: 500 });
    out.push(...page.blobs);
    cursor = page.hasMore ? page.cursor : null;
  } while (cursor);
  return out;
}

async function readAll(prefix) {
  const blobs = await listAll(prefix);
  const rows = await Promise.all(blobs.map(b => readJSON(b.pathname).catch(() => null)));
  return rows.filter(Boolean);
}

/* ---------- token records ---------- */

function normToken(t) {
  return String(t || '').trim().toUpperCase().replace(/[^A-Z0-9-]/g, '');
}

async function getToken(tokenRaw) {
  const token = normToken(tokenRaw);
  if (!token) return null;
  let rec = await readJSON(pathFor('tk', token));
  if (!rec && SEED_TOKENS.indexOf(token) > -1) {
    rec = {
      token,
      note: token === MASTER_TOKEN ? 'Master key' : 'Seeded',
      revoked: false,
      boundDeviceId: null,
      boundAt: null,
      accountId: null,
      username: null,
      createdAt: Date.now()
    };
    await writeJSON(pathFor('tk', token), rec);
  }
  return rec;
}
async function saveToken(rec) {
  return writeJSON(pathFor('tk', rec.token), rec);
}

/* ---------- account records ---------- */

function normUser(u) {
  return String(u || '').trim().toLowerCase();
}
async function getAccount(username) {
  return readJSON(pathFor('ac', normUser(username)));
}
async function saveAccount(acc) {
  return writeJSON(pathFor('ac', acc.username), acc);
}
function publicAccount(acc) {
  return {
    id: acc.id, username: acc.username, name: acc.name,
    baseline: acc.baseline, examDate: acc.examDate,
    token: acc.token, isMaster: acc.token === MASTER_TOKEN,
    createdAt: acc.createdAt, revoked: !!acc.revoked
  };
}

/* ---------- data snapshot ---------- */

async function getData(accountId) {
  return readJSON(pathFor('dt', accountId));
}
async function saveData(accountId, data) {
  return writeJSON(pathFor('dt', accountId), data);
}

/* ---------- auth resolution ---------- */

async function resolve(sid) {
  const s = readSession(sid);
  if (!s) return { error: 'Session expired. Please log in again.', code: 401 };
  const acc = await getAccount(s.username);
  if (!acc) return { error: 'Account no longer exists.', code: 401 };
  if (acc.revoked) return { error: 'Access to this account has been revoked.', code: 403 };
  const tk = await getToken(acc.token);
  if (!tk || tk.revoked) return { error: 'Your access token has been revoked.', code: 403 };
  return { acc, tk };
}

/* ============================================================
   HANDLER
   ============================================================ */

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  // Open /api/store in a browser to self-diagnose. Reports only booleans
  // and counts — never the token itself.
  if (req.method === 'GET') {
    const out = {
      ok: true,
      service: 'mortar-pestle',
      ts: Date.now(),
      blobTokenPresent: !!process.env.BLOB_READ_WRITE_TOKEN,
      secretConfigured: !!process.env.MP_SECRET,
      deployment: process.env.VERCEL_ENV || 'unknown',
      node: process.version
    };
    if (!out.blobTokenPresent) {
      out.ok = false;
      out.diagnosis = 'BLOB_READ_WRITE_TOKEN is not visible to this deployment. ' +
        'Connect the blob store to THIS project, then redeploy — env vars are ' +
        'baked in at build time, so an existing deployment will not pick it up.';
      return res.status(200).json(out);
    }
    try {
      const probe = await list({ limit: 1 });
      out.blobReachable = true;
      out.storeHasObjects = (probe.blobs || []).length > 0;
      out.diagnosis = 'Healthy. Accounts and sync should work.';
    } catch (e) {
      out.ok = false;
      out.blobReachable = false;
      out.diagnosis = 'Token present but the store rejected the request: ' +
        (e && e.message ? e.message : String(e));
    }
    return res.status(200).json(out);
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }
  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    return res.status(500).json({
      ok: false,
      error: 'Blob store not connected. Link "digitalsatpestl-blob" to this project in Vercel → Storage.'
    });
  }

  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = {}; } }
  body = body || {};
  const action = body.action;

  try {
    switch (action) {

      /* -------- 1. redeem a token onto this browser -------- */
      case 'redeem': {
        const token = normToken(body.token);
        const deviceId = String(body.deviceId || '').slice(0, 64);
        if (!token) return res.status(400).json({ ok: false, error: 'Enter your access token.' });
        if (!deviceId) return res.status(400).json({ ok: false, error: 'Browser fingerprint missing.' });

        const rec = await getToken(token);
        if (!rec) return res.status(403).json({ ok: false, error: 'Token not recognised.' });
        if (rec.revoked) return res.status(403).json({ ok: false, error: 'This token has been revoked.' });

        if (rec.boundDeviceId && rec.boundDeviceId !== deviceId) {
          // If an account exists the client can send them straight to the login form,
          // which is the whole point of having one.
          return res.status(403).json({
            ok: false,
            hasAccount: !!rec.username,
            username: rec.username || null,
            error: rec.username
              ? 'This token is already in use. Log in with your account instead.'
              : 'This token has already been redeemed on another browser.'
          });
        }
        if (!rec.boundDeviceId) {
          rec.boundDeviceId = deviceId;
          rec.boundAt = Date.now();
          await saveToken(rec);
        }
        return res.status(200).json({
          ok: true,
          token: rec.token,
          isMaster: rec.token === MASTER_TOKEN,
          hasAccount: !!rec.username,
          username: rec.username || null
        });
      }

      /* -------- 2. create the permanent account -------- */
      case 'signup': {
        const token = normToken(body.token);
        const deviceId = String(body.deviceId || '').slice(0, 64);
        const username = normUser(body.username);
        const password = String(body.password || '');

        if (!/^[a-z0-9._-]{3,24}$/.test(username)) {
          return res.status(400).json({ ok: false, error: 'User ID: 3–24 characters, letters/numbers/. _ - only.' });
        }
        if (password.length < 6) {
          return res.status(400).json({ ok: false, error: 'Password must be at least 6 characters.' });
        }

        const rec = await getToken(token);
        if (!rec) return res.status(403).json({ ok: false, error: 'Token not recognised.' });
        if (rec.revoked) return res.status(403).json({ ok: false, error: 'This token has been revoked.' });
        if (rec.boundDeviceId && rec.boundDeviceId !== deviceId) {
          return res.status(403).json({ ok: false, error: 'This token belongs to another browser.' });
        }
        if (rec.username) {
          return res.status(409).json({ ok: false, error: 'This token already has an account (' + rec.username + '). Log in instead.' });
        }
        if (await getAccount(username)) {
          return res.status(409).json({ ok: false, error: 'That user ID is taken.' });
        }

        const salt = crypto.randomBytes(16).toString('hex');
        const acc = {
          id: 'u_' + crypto.randomBytes(9).toString('hex'),
          username,
          name: String(body.name || '').slice(0, 60) || username,
          baseline: body.baseline == null ? null : Number(body.baseline),
          examDate: String(body.examDate || '').slice(0, 10),
          token: rec.token,
          salt,
          hash: hashPassword(password, salt),
          revoked: false,
          createdAt: Date.now()
        };
        await saveAccount(acc);

        rec.username = username;
        rec.accountId = acc.id;
        if (!rec.boundDeviceId) { rec.boundDeviceId = deviceId; rec.boundAt = Date.now(); }
        await saveToken(rec);

        const snapshot = body.snapshot && typeof body.snapshot === 'object' ? body.snapshot : {};
        snapshot.rev = 1;
        snapshot.savedAt = Date.now();
        await saveData(acc.id, snapshot);

        return res.status(200).json({
          ok: true,
          sid: signSession({ username, id: acc.id, exp: Date.now() + SESSION_DAYS * 864e5 }),
          account: publicAccount(acc),
          data: snapshot
        });
      }

      /* -------- 3. log in from anywhere -------- */
      case 'login': {
        const username = normUser(body.username);
        const password = String(body.password || '');
        const acc = await getAccount(username);
        await new Promise(r => setTimeout(r, 150)); // blunt the brute-force edge

        if (!acc || !safeEq(hashPassword(password, acc.salt), acc.hash)) {
          return res.status(401).json({ ok: false, error: 'Wrong user ID or password.' });
        }
        if (acc.revoked) return res.status(403).json({ ok: false, error: 'Access to this account has been revoked.' });
        const tk = await getToken(acc.token);
        if (!tk || tk.revoked) return res.status(403).json({ ok: false, error: 'Your access token has been revoked.' });

        const data = (await getData(acc.id)) || {};
        return res.status(200).json({
          ok: true,
          sid: signSession({ username, id: acc.id, exp: Date.now() + SESSION_DAYS * 864e5 }),
          account: publicAccount(acc),
          data
        });
      }

      /* -------- 4. pull the cloud snapshot -------- */
      case 'pull': {
        const r = await resolve(body.sid);
        if (r.error) return res.status(r.code).json({ ok: false, error: r.error });
        const data = (await getData(r.acc.id)) || {};
        return res.status(200).json({ ok: true, account: publicAccount(r.acc), data });
      }

      /* -------- 5. push the local snapshot -------- */
      case 'push': {
        const r = await resolve(body.sid);
        if (r.error) return res.status(r.code).json({ ok: false, error: r.error });
        const data = (body.data && typeof body.data === 'object') ? body.data : {};
        const prev = (await getData(r.acc.id)) || {};
        data.rev = (prev.rev || 0) + 1;
        data.savedAt = Date.now();
        await saveData(r.acc.id, data);
        return res.status(200).json({ ok: true, rev: data.rev, savedAt: data.savedAt });
      }

      /* -------- 6. profile edit -------- */
      case 'profile': {
        const r = await resolve(body.sid);
        if (r.error) return res.status(r.code).json({ ok: false, error: r.error });
        const acc = r.acc;
        if (body.name != null) acc.name = String(body.name).slice(0, 60);
        if (body.baseline !== undefined) acc.baseline = body.baseline == null ? null : Number(body.baseline);
        if (body.examDate != null) acc.examDate = String(body.examDate).slice(0, 10);
        if (body.newPassword) {
          if (String(body.newPassword).length < 6) {
            return res.status(400).json({ ok: false, error: 'Password must be at least 6 characters.' });
          }
          if (!safeEq(hashPassword(String(body.oldPassword || ''), acc.salt), acc.hash)) {
            return res.status(401).json({ ok: false, error: 'Current password is wrong.' });
          }
          acc.salt = crypto.randomBytes(16).toString('hex');
          acc.hash = hashPassword(String(body.newPassword), acc.salt);
        }
        await saveAccount(acc);
        return res.status(200).json({ ok: true, account: publicAccount(acc) });
      }

      /* -------- 7. admin (master token only) -------- */
      case 'admin': {
        const r = await resolve(body.sid);
        if (r.error) return res.status(r.code).json({ ok: false, error: r.error });
        if (r.acc.token !== MASTER_TOKEN) {
          return res.status(403).json({ ok: false, error: 'Administrator privileges required.' });
        }
        const op = body.op;

        if (op === 'overview') {
          const tokens = await readAll('tk/');
          const accounts = (await readAll('ac/')).map(publicAccount);
          for (const t of SEED_TOKENS) {
            if (!tokens.find(x => x.token === t)) await getToken(t);
          }
          const tokens2 = await readAll('tk/');
          return res.status(200).json({
            ok: true,
            tokens: tokens2.sort((a, b) => a.token.localeCompare(b.token)),
            accounts: accounts.sort((a, b) => a.username.localeCompare(b.username))
          });
        }

        if (op === 'tokenAdd') {
          const t = normToken(body.token);
          if (t.length < 4) return res.status(400).json({ ok: false, error: 'Token must be at least 4 characters.' });
          if (await readJSON(pathFor('tk', t))) return res.status(409).json({ ok: false, error: 'That token already exists.' });
          await saveToken({
            token: t, note: String(body.note || '').slice(0, 80), revoked: false,
            boundDeviceId: null, boundAt: null, accountId: null, username: null, createdAt: Date.now()
          });
          return res.status(200).json({ ok: true });
        }

        if (op === 'tokenRevoke' || op === 'tokenRestore') {
          const t = normToken(body.token);
          if (t === MASTER_TOKEN) return res.status(400).json({ ok: false, error: 'The master key cannot be revoked.' });
          const rec = await getToken(t);
          if (!rec) return res.status(404).json({ ok: false, error: 'No such token.' });
          rec.revoked = (op === 'tokenRevoke');
          await saveToken(rec);
          if (rec.username) {
            const acc = await getAccount(rec.username);
            if (acc) { acc.revoked = rec.revoked; await saveAccount(acc); }
          }
          return res.status(200).json({ ok: true });
        }

        if (op === 'tokenUnbind') {
          const rec = await getToken(normToken(body.token));
          if (!rec) return res.status(404).json({ ok: false, error: 'No such token.' });
          rec.boundDeviceId = null; rec.boundAt = null;
          await saveToken(rec);
          return res.status(200).json({ ok: true });
        }

        if (op === 'tokenDelete') {
          const t = normToken(body.token);
          if (t === MASTER_TOKEN) return res.status(400).json({ ok: false, error: 'The master key cannot be deleted.' });
          await del(pathFor('tk', t)).catch(e => { if (!isNotFound(e)) throw e; });
          return res.status(200).json({ ok: true });
        }

        if (op === 'accountRevoke' || op === 'accountRestore') {
          const acc = await getAccount(body.username);
          if (!acc) return res.status(404).json({ ok: false, error: 'No such account.' });
          if (acc.token === MASTER_TOKEN) return res.status(400).json({ ok: false, error: 'The master account cannot be revoked.' });
          acc.revoked = (op === 'accountRevoke');
          await saveAccount(acc);
          return res.status(200).json({ ok: true });
        }

        if (op === 'accountReset') {
          const acc = await getAccount(body.username);
          if (!acc) return res.status(404).json({ ok: false, error: 'No such account.' });
          const pw = String(body.newPassword || '');
          if (pw.length < 6) return res.status(400).json({ ok: false, error: 'Password must be at least 6 characters.' });
          acc.salt = crypto.randomBytes(16).toString('hex');
          acc.hash = hashPassword(pw, acc.salt);
          await saveAccount(acc);
          return res.status(200).json({ ok: true });
        }

        if (op === 'accountDelete') {
          const acc = await getAccount(body.username);
          if (!acc) return res.status(404).json({ ok: false, error: 'No such account.' });
          if (acc.token === MASTER_TOKEN) return res.status(400).json({ ok: false, error: 'The master account cannot be deleted.' });
          for (const p of [pathFor('ac', acc.username), pathFor('dt', acc.id)]) {
            await del(p).catch(e => { if (!isNotFound(e)) throw e; });
          }
          const rec = await getToken(acc.token);
          if (rec) { rec.username = null; rec.accountId = null; rec.boundDeviceId = null; rec.boundAt = null; await saveToken(rec); }
          return res.status(200).json({ ok: true });
        }

        return res.status(400).json({ ok: false, error: 'Unknown admin operation.' });
      }

      default:
        return res.status(400).json({ ok: false, error: 'Unknown action.' });
    }
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'Server error: ' + (e && e.message ? e.message : String(e)) });
  }
}
