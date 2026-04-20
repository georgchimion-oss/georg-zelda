// georg-ops.js — Analytics tracker + audit questionnaire + admin dashboards.
// Two sets of routes:
//   1) Public POST endpoints on /ops (mounted onto penny's ops router):
//        POST /ops/track           — visitor pageview ping (CORS)
//        POST /ops/audit-request   — questionnaire submission → JSONL + Slack (CORS)
//   2) Cookie-authed admin pages on /admin (mounted on main app, via nginx /admin/):
//        GET  /admin               — login form (or redirect to /admin/visits if authed)
//        POST /admin/login         — validates password → sets cookie → redirects
//        GET  /admin/visits        — analytics dashboard
//        GET  /admin/requests      — audit-request list
//        GET  /admin/logout        — clears cookie → redirects to /admin

const express = require('express');
const fs = require('fs');
const https = require('https');
const path = require('path');
const crypto = require('crypto');

// htpasswd-js: validates username/password against apache htpasswd files (APR1/bcrypt).
// Installed via: npm install htpasswd-js (inside /var/www/penny).
let htpasswd = null;
try { htpasswd = require('htpasswd-js'); } catch (e) { /* optional dep */ }

const DATA_DIR = '/root/georg-data';
const VISITS_LOG = path.join(DATA_DIR, 'visits.jsonl');
const REQUESTS_LOG = path.join(DATA_DIR, 'audit-requests.jsonl');
const SLACK_TOKEN_FILE = '/root/.secrets/slack-bot-token.txt';
const SLACK_CHANNEL = '#audit-requests';
const ADMIN_COOKIE = 'georg_admin';

try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}

// ─── Slack ──────────────────────────────────────────────────────────────────
function getSlackToken() {
  try { return fs.readFileSync(SLACK_TOKEN_FILE, 'utf8').trim(); }
  catch (e) { return null; }
}

function postSlack(channel, text, blocks) {
  const token = getSlackToken();
  if (!token) return Promise.reject(new Error('no slack token at ' + SLACK_TOKEN_FILE));
  const body = JSON.stringify({ channel, text, blocks });
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'slack.com',
      path: '/api/chat.postMessage',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Authorization': 'Bearer ' + token,
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (!parsed.ok) return reject(new Error(parsed.error || 'slack error'));
          resolve(parsed);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Helpers ────────────────────────────────────────────────────────────────
function cors(req, res, next) {
  const origin = req.headers.origin || '';
  if (/^https?:\/\/([a-z0-9-]+\.)?georg\.miami$/.test(origin) || origin === 'http://localhost:8742') {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
}

function getIP(req) {
  return ((req.headers['x-forwarded-for'] || req.ip || '') + '')
    .split(',')[0].trim();
}

function esc(s) {
  return String(s || '').replace(/[<>&"']/g, c => (
    { '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

async function readJsonl(file) {
  try {
    const raw = await fs.promises.readFile(file, 'utf8');
    return raw.split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch (e) { return null; }
    }).filter(Boolean);
  } catch (e) { return []; }
}

function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const pair of raw.split('; ')) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    if (pair.slice(0, idx).trim() === name) return pair.slice(idx + 1).trim();
  }
  return null;
}

// ─── Dashboard HTML renderers (shared by /admin routes) ─────────────────────
async function renderVisitsHtml() {
  const rows = await readJsonl(VISITS_LOG);
  const requests = await readJsonl(REQUESTS_LOG);
  const now = Date.now();
  const day = 86400000;

  const filter = (cutoff) => rows.filter(r => now - r.ts < cutoff && !r.owner);
  const last24 = filter(day);
  const last7 = filter(7 * day);
  const last30 = filter(30 * day);
  const uniques = rs => new Set(rs.map(r => r.vid)).size;

  const pageCount = {};
  last30.forEach(r => { pageCount[r.page] = (pageCount[r.page] || 0) + 1; });
  const topPages = Object.entries(pageCount).sort((a, b) => b[1] - a[1]).slice(0, 15);

  const refCount = {};
  last30.forEach(r => {
    if (!r.ref) return;
    try {
      const host = new URL(r.ref).hostname;
      if (host.endsWith('georg.miami')) return;
      refCount[host] = (refCount[host] || 0) + 1;
    } catch (e) {}
  });
  const topRefs = Object.entries(refCount).sort((a, b) => b[1] - a[1]).slice(0, 10);

  const visitorRows = {};
  for (const r of rows) {
    if (r.owner) continue;
    if (!visitorRows[r.vid]) visitorRows[r.vid] = [];
    visitorRows[r.vid].push(r);
  }
  const visitors = Object.entries(visitorRows)
    .sort((a, b) => b[1][b[1].length - 1].ts - a[1][a[1].length - 1].ts)
    .slice(0, 20);

  const rel = ts => {
    const s = Math.floor((now - ts) / 1000);
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  };

  return `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Georg · Analytics</title>
<style>
  body{font-family:-apple-system,SF Pro,sans-serif;background:#0a0a0a;color:#eee;margin:0;padding:32px;line-height:1.5;max-width:1100px}
  .topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
  h1{font-size:20px;margin:0;letter-spacing:-0.01em}
  .nav{display:flex;gap:14px;font-size:12px}
  .nav a{color:#6AE3FF;text-decoration:none}
  .nav a:hover{text-decoration:underline}
  .nav .logout{color:#888}
  h2{font-size:12px;text-transform:uppercase;letter-spacing:0.1em;color:#6AE3FF;margin:36px 0 12px}
  .meta{color:#888;font-size:12px;margin-bottom:12px}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
  .stat{background:#141414;border:1px solid #222;border-radius:8px;padding:14px 16px}
  .stat .big{font-size:26px;font-weight:700;color:#fff;line-height:1.1}
  .stat .lbl{font-size:10px;color:#888;text-transform:uppercase;letter-spacing:0.08em;margin-top:6px}
  table{width:100%;border-collapse:collapse;font-size:13px;background:#141414;border:1px solid #222;border-radius:8px;overflow:hidden}
  th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #222}
  th{background:#1a1a1a;color:#aaa;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:0.08em}
  tr:last-child td{border-bottom:none}
  td.page{font-family:SF Mono,Menlo,monospace;font-size:12px}
  td.num{text-align:right;color:#6AE3FF;font-weight:600;width:80px}
  .visitor{background:#141414;border:1px solid #222;border-radius:8px;padding:12px 16px;margin-bottom:8px}
  .visitor .vid{font-family:SF Mono,monospace;font-size:11px;color:#888;margin-bottom:4px}
  .visitor .path{font-size:12px;color:#ccc;font-family:SF Mono,monospace;line-height:1.7}
  .visitor .path b{color:#FFD36E}
  .notice{background:#1a2030;border:1px solid #2a3050;border-radius:8px;padding:14px 16px;margin:16px 0;font-size:14px}
  .notice b{color:#6AE3FF;font-size:18px}
  .empty{color:#555;padding:24px;text-align:center;font-size:13px}
</style></head>
<body>
<div class="topbar">
  <h1>Georg · Analytics</h1>
  <div class="nav">
    <a href="/admin/visits">Visits</a>
    <a href="/admin/requests">Requests (${requests.length})</a>
    <a class="logout" href="/admin/logout">Log out</a>
  </div>
</div>
<div class="meta">${new Date().toLocaleString('en-US', { timeZone: 'America/New_York' })} · your visits filtered out</div>

<h2>Overview</h2>
<div class="stats">
  <div class="stat"><div class="big">${last24.length}</div><div class="lbl">Pageviews · 24h</div></div>
  <div class="stat"><div class="big">${uniques(last24)}</div><div class="lbl">Unique · 24h</div></div>
  <div class="stat"><div class="big">${last7.length}</div><div class="lbl">Pageviews · 7d</div></div>
  <div class="stat"><div class="big">${uniques(last7)}</div><div class="lbl">Unique · 7d</div></div>
  <div class="stat"><div class="big">${last30.length}</div><div class="lbl">Pageviews · 30d</div></div>
  <div class="stat"><div class="big">${uniques(last30)}</div><div class="lbl">Unique · 30d</div></div>
</div>

<div class="notice">
  <b>${requests.length}</b> audit request${requests.length === 1 ? '' : 's'} submitted — <a href="/admin/requests">view all →</a>
</div>

<h2>Top pages · 30d</h2>
<table>
  <tr><th>Page</th><th style="text-align:right">Views</th></tr>
  ${topPages.length ? topPages.map(([page, n]) =>
    `<tr><td class="page">${esc(page)}</td><td class="num">${n}</td></tr>`
  ).join('') : '<tr><td colspan="2" class="empty">No visits yet</td></tr>'}
</table>

<h2>Top referrers · 30d</h2>
<table>
  <tr><th>Source</th><th style="text-align:right">Visits</th></tr>
  ${topRefs.length ? topRefs.map(([host, n]) =>
    `<tr><td class="page">${esc(host)}</td><td class="num">${n}</td></tr>`
  ).join('') : '<tr><td colspan="2" class="empty">No external referrers yet</td></tr>'}
</table>

<h2>Recent visitors · last 20</h2>
${visitors.length ? visitors.map(([vid, visits]) => `
  <div class="visitor">
    <div class="vid">${esc(vid.slice(0, 13))}  ·  ${visits.length} page${visits.length === 1 ? '' : 's'}  ·  ${rel(visits[visits.length - 1].ts)}</div>
    <div class="path">${visits.map((v, i) => (i > 0 ? ' → ' : '') + `<b>${esc(v.page.replace('georg.miami', ''))}</b>`).join('')}</div>
  </div>
`).join('') : '<div class="empty">No visitors yet</div>'}
</body></html>`;
}

async function renderRequestsHtml() {
  const rows = (await readJsonl(REQUESTS_LOG)).reverse();
  return `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Georg · Audit Requests</title>
<style>
  body{font-family:-apple-system,sans-serif;background:#0a0a0a;color:#eee;margin:0;padding:32px;line-height:1.5;max-width:900px}
  .topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
  h1{font-size:20px;margin:0}
  .nav{display:flex;gap:14px;font-size:12px}
  .nav a{color:#6AE3FF;text-decoration:none}
  .nav a:hover{text-decoration:underline}
  .nav .logout{color:#888}
  .req{background:#141414;border:1px solid #222;border-radius:8px;padding:16px 20px;margin-bottom:12px}
  .req .head{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px;gap:12px}
  .req .name{font-weight:700;font-size:16px}
  .req .time{color:#888;font-size:12px;white-space:nowrap}
  .req .grid{display:grid;grid-template-columns:110px 1fr;gap:4px 16px;font-size:13px;margin-top:10px}
  .req .lbl{color:#888;text-transform:uppercase;font-size:10px;letter-spacing:0.08em;padding-top:3px}
  .req .val a{color:#6AE3FF;text-decoration:none}
  .pain{background:#0e141e;border-left:2px solid #6AE3FF;padding:10px 14px;font-size:13px;margin-top:12px;white-space:pre-wrap;line-height:1.5}
  .pain-list{color:#ccc;font-size:13px;margin:10px 0 0;padding-left:20px}
  .pain-list li{margin:2px 0}
  .empty{color:#555;padding:40px;text-align:center}
</style></head>
<body>
<div class="topbar">
  <h1>Audit Requests (${rows.length})</h1>
  <div class="nav">
    <a href="/admin/visits">Visits</a>
    <a href="/admin/requests">Requests</a>
    <a class="logout" href="/admin/logout">Log out</a>
  </div>
</div>
${rows.length ? rows.map(r => `
  <div class="req">
    <div class="head">
      <span class="name">${esc(r.name)}${r.company ? ` <span style="color:#888;font-weight:400">· ${esc(r.company)}</span>` : ''}</span>
      <span class="time">${new Date(r.ts).toLocaleString('en-US', { timeZone: 'America/New_York' })}</span>
    </div>
    <div class="grid">
      <div class="lbl">Email</div><div class="val"><a href="mailto:${esc(r.email)}">${esc(r.email)}</a></div>
      <div class="lbl">Industry</div><div class="val">${esc(r.industry || '—')}</div>
      <div class="lbl">Budget</div><div class="val">${esc(r.budget || '—')}</div>
      <div class="lbl">Timeline</div><div class="val">${esc(r.timeline || '—')}</div>
    </div>
    ${r.pain && r.pain.length ? '<ul class="pain-list">' + r.pain.map(p => '<li>' + esc(p) + '</li>').join('') + '</ul>' : ''}
    ${r.painText ? '<div class="pain">' + esc(r.painText) + '</div>' : ''}
    <div style="color:#555;font-size:10px;margin-top:10px;font-family:SF Mono,monospace">${esc(r.id)} · ${esc(r.ip || '')}</div>
  </div>
`).join('') : '<div class="empty">No requests yet</div>'}
</body></html>`;
}

function loginHtml(errorMsg) {
  return `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Georg · Admin</title>
<style>
  body{font-family:-apple-system,sans-serif;background:#0a0a0a;color:#eee;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
  .card{background:#141414;border:1px solid #222;border-radius:12px;padding:40px 36px;max-width:380px;width:100%}
  h1{font-size:22px;margin:0 0 8px;letter-spacing:-0.01em}
  p{color:#888;font-size:13px;margin:0 0 28px}
  label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#888;margin-bottom:8px;margin-top:14px}
  label:first-of-type{margin-top:0}
  input{width:100%;background:#0a0a0a;border:1px solid #222;border-radius:6px;padding:12px 14px;font-size:15px;color:#eee;font-family:inherit;transition:border-color .15s}
  input:focus{outline:none;border-color:#6AE3FF;box-shadow:0 0 0 3px rgba(106,227,255,0.15)}
  button{margin-top:20px;width:100%;background:#6AE3FF;color:#0a0a0a;border:none;border-radius:6px;padding:12px;font-weight:700;font-size:14px;letter-spacing:0.02em;cursor:pointer;transition:background .15s}
  button:hover{background:#a0eaff}
  .err{background:rgba(255,80,80,0.1);border:1px solid rgba(255,80,80,0.3);color:#ff9090;padding:10px 12px;border-radius:6px;font-size:13px;margin-bottom:16px}
  .hint{font-size:11px;color:#555;margin-top:18px;text-align:center;font-family:SF Mono,monospace}
</style></head>
<body>
<form class="card" method="post" action="/admin/login">
  <h1>Georg · Admin</h1>
  <p>Sign in to view analytics and audit requests.</p>
  ${errorMsg ? `<div class="err">${esc(errorMsg)}</div>` : ''}
  <label for="un">Username</label>
  <input type="text" id="un" name="username" autofocus required autocomplete="username" autocapitalize="off" spellcheck="false">
  <label for="pw">Password</label>
  <input type="password" id="pw" name="password" required autocomplete="current-password">
  <button type="submit">Sign in</button>
  <div class="hint">georg.miami/admin</div>
</form>
</body></html>`;
}

// ─── Register /ops/* routes (public API) ────────────────────────────────────
function register(router /*, opsAuth */) {

  router.post('/track', cors, express.json({ limit: '8kb' }), (req, res) => {
    try {
      const { page, ref, vid, owner, ts } = req.body || {};
      if (!page || !vid) return res.status(400).end();
      const row = {
        page: String(page).slice(0, 500),
        ref: ref ? String(ref).slice(0, 500) : null,
        vid: String(vid).slice(0, 80),
        owner: !!owner,
        ts: typeof ts === 'number' ? ts : Date.now(),
        ip: getIP(req),
        ua: (req.headers['user-agent'] || '').toString().slice(0, 200),
      };
      fs.appendFile(VISITS_LOG, JSON.stringify(row) + '\n', () => {});
    } catch (e) {}
    res.status(204).end();
  });
  router.options('/track', cors);

  router.post('/audit-request', cors, express.json({ limit: '32kb' }), async (req, res) => {
    try {
      const { name, email, company, industry, pain, painText, budget, timeline } = req.body || {};
      if (!name || !email) return res.status(400).json({ error: 'name and email required' });
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email))) return res.status(400).json({ error: 'invalid email' });

      const id = 'req_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      const row = {
        id,
        name: String(name).slice(0, 200),
        email: String(email).slice(0, 200),
        company: String(company || '').slice(0, 200),
        industry: String(industry || '').slice(0, 80),
        pain: Array.isArray(pain) ? pain.slice(0, 20).map(p => String(p).slice(0, 200)) : [],
        painText: String(painText || '').slice(0, 2000),
        budget: String(budget || '').slice(0, 40),
        timeline: String(timeline || '').slice(0, 40),
        ts: Date.now(),
        ip: getIP(req),
        ua: (req.headers['user-agent'] || '').toString().slice(0, 200),
      };
      await fs.promises.appendFile(REQUESTS_LOG, JSON.stringify(row) + '\n');

      const fallbackText = `New audit request from ${row.name}` + (row.company ? ` at ${row.company}` : '');
      const blocks = [
        { type: 'header', text: { type: 'plain_text', text: 'New Growth Audit Request', emoji: false } },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Name:*\n${row.name}` },
            { type: 'mrkdwn', text: `*Email:*\n<mailto:${row.email}|${row.email}>` },
            { type: 'mrkdwn', text: `*Company:*\n${row.company || '_(not provided)_'}` },
            { type: 'mrkdwn', text: `*Industry:*\n${row.industry || '_(none)_'}` },
            { type: 'mrkdwn', text: `*Budget:*\n${row.budget || '_(none)_'}` },
            { type: 'mrkdwn', text: `*Timeline:*\n${row.timeline || '_(none)_'}` },
          ],
        },
        ...(row.pain.length ? [{ type: 'section', text: { type: 'mrkdwn', text: `*Pain points:*\n• ${row.pain.join('\n• ')}` } }] : []),
        ...(row.painText ? [{ type: 'section', text: { type: 'mrkdwn', text: `*Notes:*\n${row.painText}` } }] : []),
        { type: 'context', elements: [{ type: 'mrkdwn', text: `\`${row.id}\` · ${new Date(row.ts).toISOString()}` }] },
      ];

      postSlack(SLACK_CHANNEL, fallbackText, blocks)
        .catch(e => console.error('[georg-ops] slack error:', e.message));

      res.json({ ok: true, id });
    } catch (e) {
      console.error('[georg-ops] audit-request error:', e);
      res.status(500).json({ error: 'internal error' });
    }
  });
  router.options('/audit-request', cors);
}

// ─── Register /admin/* routes (cookie-authed dashboards) ─────────────────────
// Credentials: hardcoded single admin user. Cookie value is opsAuthToken so
// there's still one secret to rotate if needed (via /var/www/penny/.env).
const ADMIN_USER = 'georg';
const ADMIN_PASS = 'miami123!';

function registerAdmin(app, opsAuthToken) {

  function isAuthed(req) {
    return readCookie(req, ADMIN_COOKIE) === opsAuthToken;
  }
  function gate(req, res, next) {
    if (isAuthed(req)) return next();
    return res.redirect('/admin');
  }

  app.get('/admin', (req, res) => {
    if (isAuthed(req)) return res.redirect('/admin/visits');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(loginHtml());
  });

  app.post('/admin/login', express.urlencoded({ extended: false, limit: '4kb' }), (req, res) => {
    const user = (req.body && req.body.username || '').trim();
    const pw = (req.body && req.body.password) || '';
    if (user !== ADMIN_USER || pw !== ADMIN_PASS) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(loginHtml('Wrong username or password.'));
    }
    const maxAgeSec = 30 * 24 * 3600;
    res.setHeader('Set-Cookie',
      `${ADMIN_COOKIE}=${encodeURIComponent(opsAuthToken)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSec}`
    );
    res.redirect('/admin/visits');
  });

  app.get('/admin/logout', (req, res) => {
    res.setHeader('Set-Cookie', `${ADMIN_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
    res.redirect('/admin');
  });

  app.get('/admin/visits', gate, async (req, res) => {
    try {
      const html = await renderVisitsHtml();
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(html);
    } catch (e) {
      console.error('[georg-ops] /admin/visits error:', e);
      res.status(500).send('Error');
    }
  });

  app.get('/admin/requests', gate, async (req, res) => {
    try {
      const html = await renderRequestsHtml();
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(html);
    } catch (e) {
      console.error('[georg-ops] /admin/requests error:', e);
      res.status(500).send('Error');
    }
  });
}

// ─── Register /_gate/* routes (cookie-based site gate) ─────────────────────
// Maps each gated subdomain to the htpasswd file that contains valid creds.
// Penny validates on POST /_gate/login, sets a signed cookie, then nginx
// uses auth_request → /_gate/check to gate all requests to the site.
const HTPASSWD_MAP = {
  'rcg.georg.miami': '/etc/nginx/.htpasswd-audits',
  'step2.georg.miami': '/etc/nginx/.htpasswd-audits',
  'dumbo-health.georg.miami': '/etc/nginx/.htpasswd-audits',
  'ian.georg.miami': '/etc/nginx/.htpasswd-audits',
  'buildrite.georg.miami': '/etc/nginx/.htpasswd-audits',
  'rbc-datacenter.georg.miami': '/etc/nginx/.htpasswd-audits',
  'dram-finance.georg.miami': '/etc/nginx/.htpasswd-audits',
  'propertyforce.georg.miami': '/etc/nginx/.htpasswd-audits',
  'coleman.georg.miami': '/etc/nginx/htpasswd-coleman',
  'thesolerevival.georg.miami': '/etc/nginx/htpasswd-thesolerevival',
  'mockup-thesolerevival.georg.miami': '/etc/nginx/htpasswd-mockup-thesolerevival',
};
const GATE_COOKIE_MAX_AGE = 30 * 24 * 3600; // 30 days

function siteFromHost(host) {
  return String(host || '').toLowerCase().split(':')[0];
}
function gateCookieName(host) {
  return 'gate_' + siteFromHost(host).split('.')[0].replace(/[^a-z0-9]/g, '');
}
function signGateToken(host, secret) {
  const ts = Date.now().toString();
  const sig = crypto.createHmac('sha256', secret).update(siteFromHost(host) + ':' + ts).digest('hex').slice(0, 32);
  return ts + '.' + sig;
}
function verifyGateToken(host, token, secret) {
  if (!token) return false;
  const [ts, sig] = token.split('.');
  if (!ts || !sig) return false;
  const age = Date.now() - parseInt(ts, 10);
  if (isNaN(age) || age < 0 || age > GATE_COOKIE_MAX_AGE * 1000) return false;
  const expected = crypto.createHmac('sha256', secret).update(siteFromHost(host) + ':' + ts).digest('hex').slice(0, 32);
  // constant-time-ish compare
  return sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

function registerGate(app, secret) {
  if (!htpasswd) {
    console.error('[georg-ops] htpasswd-js not installed — /_gate routes disabled');
    return;
  }

  // nginx calls this via auth_request on every request to a gated site.
  // Returns 200 if the cookie proves the user logged in; 401 otherwise.
  app.get('/_gate/check', (req, res) => {
    const host = siteFromHost(req.headers.host);
    if (!HTPASSWD_MAP[host]) {
      // Site isn't in our gated map — fail closed
      return res.status(401).end();
    }
    const token = readCookie(req, gateCookieName(host));
    if (!verifyGateToken(host, token, secret)) return res.status(401).end();
    res.status(200).end();
  });

  // User POSTs {user, pass} here after typing creds in the login page.
  app.post('/_gate/login', express.json({ limit: '4kb' }), async (req, res) => {
    try {
      const host = siteFromHost(req.headers.host);
      const htpasswdFile = HTPASSWD_MAP[host];
      if (!htpasswdFile) return res.status(400).json({ error: 'unknown site' });

      const user = ((req.body && req.body.user) || '').trim();
      const pass = (req.body && req.body.pass) || '';
      if (!user || !pass) return res.status(400).json({ error: 'missing credentials' });

      const ok = await htpasswd.authenticate({ username: user, password: pass, file: htpasswdFile });
      if (!ok) return res.status(401).json({ error: 'wrong username or password' });

      const token = signGateToken(host, secret);
      res.setHeader('Set-Cookie',
        `${gateCookieName(host)}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${GATE_COOKIE_MAX_AGE}`
      );
      res.json({ ok: true });
    } catch (e) {
      console.error('[georg-ops] /_gate/login error:', e);
      res.status(500).json({ error: 'internal error' });
    }
  });

  // Optional — user-initiated logout. Clears cookie for current site.
  app.get('/_gate/logout', (req, res) => {
    const host = siteFromHost(req.headers.host);
    res.setHeader('Set-Cookie', `${gateCookieName(host)}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
    res.redirect('/');
  });
}

module.exports = { register, registerAdmin, registerGate };
