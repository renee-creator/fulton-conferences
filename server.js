// Fulton Family Conferences server
// Runs on Render. Signs teachers in with personal passcodes, keeps every child and
// conference record as a file in a private GitHub repository, and reads uploaded
// conference forms with Claude. Every failure returns a clear message.
//
// Render settings (Environment)
//   TEACHER_PASSCODES   Name=passcode pairs separated by commas, like  Hannah=maple garden 42,Chris=river stone 7
//   GITHUB_TOKEN        fine-grained token with Contents read and write on the records repository only
//   RECORDS_REPO        owner/name of the private records repository (default renee-creator/fulton-conference-records)
//   ANTHROPIC_API_KEY   the same key TREE uses
//   ALLOWED_ORIGINS     extra websites allowed to use this server, separated by commas (optional)
//
// Open this service's address in a browser to see a status page.

const http = require('http');
const https = require('https');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const MAX_BODY_BYTES = 30 * 1024 * 1024;
const FLUSH_DELAY_MS = Number(process.env.FLUSH_DELAY_MS) || 15000;   // typing is gathered into one GitHub save
const UPSTREAM_TIMEOUT_MS = 180000;
const RECORDS_REPO = (process.env.RECORDS_REPO || 'renee-creator/fulton-conference-records').trim();
const GITHUB_API = (process.env.GITHUB_API || 'https://api.github.com').replace(/\/+$/, '');
const ANTHROPIC_BASE = new URL(process.env.ANTHROPIC_API_BASE || 'https://api.anthropic.com');
const KINDS = ['children', 'conferences', 'settings'];
const ID_RE = /^[a-z0-9][a-z0-9._-]{0,150}$/i;

/* ---------- helpers ---------- */
const log = (...a) => console.log(new Date().toISOString(), ...a);
function cleanKey(raw) { return String(raw || '').replace(/[\s"'​-‍﻿]/g, ''); }
function githubToken() { return cleanKey(process.env.GITHUB_TOKEN); }
function anthropicKey() {
  const env = process.env;
  if (cleanKey(env.ANTHROPIC_API_KEY).startsWith('sk-ant-')) return cleanKey(env.ANTHROPIC_API_KEY);
  for (const n of Object.keys(env)) if (cleanKey(env[n]).startsWith('sk-ant-')) return cleanKey(env[n]);
  return '';
}

/* ---------- teacher passcodes and sessions ---------- */
function normCode(s) { return String(s == null ? '' : s).normalize('NFKC').trim().replace(/\s+/g, ' ').toLowerCase(); }
function sha(s) { return crypto.createHash('sha256').update(String(s), 'utf8').digest(); }
const PASS_RAW = String(process.env.TEACHER_PASSCODES || process.env.SCHOOL_PASSCODES || '');
const TEACHERS = PASS_RAW.split(',').map(e => e.trim()).filter(Boolean).map(e => {
  const cut = e.indexOf('=');
  const name = cut > 0 ? e.slice(0, cut).trim() : '';
  const code = normCode(cut > 0 ? e.slice(cut + 1) : e);
  return { name: /^[A-Za-z0-9 _.&'-]{1,40}$/.test(name) ? name : (cut > 0 ? '' : 'Staff'), code, hash: sha(code) };
}).filter(t => t.name && t.code.length >= 6);
const SKIPPED_PASSCODES = PASS_RAW.split(',').filter(e => e.trim()).length - TEACHERS.length;
const SECRET = sha('fulton-conferences|' + (process.env.SESSION_SECRET || '') + '|' + githubToken() + '|' + PASS_RAW);
const SESSION_DAYS = 60;

function b64u(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function sign(body) { return b64u(crypto.createHmac('sha256', SECRET).update(body).digest()); }
function makeSession(name) { const body = b64u(JSON.stringify({ n: name, e: Date.now() + SESSION_DAYS * 864e5 })); return body + '.' + sign(body); }
function readSession(req) {
  const h = String(req.headers.authorization || '');
  const tok = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  return checkSession(tok);
}
function checkSession(tok) {
  if (!tok || tok.length > 600) return null;
  const [body, mac] = tok.split('.');
  if (!body || !mac) return null;
  const want = sign(body);
  if (want.length !== mac.length || !crypto.timingSafeEqual(Buffer.from(want), Buffer.from(mac))) return null;
  let s; try { s = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); } catch (e) { return null; }
  if (!s || typeof s.n !== 'string' || !(s.e > Date.now())) return null;
  if (!TEACHERS.some(t => t.name === s.n)) return null;   // a teacher removed on Render is signed out
  return { name: s.n };
}
function matchPasscode(given) {
  if (typeof given !== 'string' || !given || given.length > 200) return null;
  const h = sha(normCode(given));
  let hit = null;
  for (const t of TEACHERS) if (crypto.timingSafeEqual(h, t.hash)) hit = t;
  return hit;
}
const wrongTries = new Map();
function who(req) { const f = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim(); return f || (req.socket && req.socket.remoteAddress) || 'unknown'; }
function blocked(ip) { const t = wrongTries.get(ip); return !!t && t.until > Date.now() && t.count >= 10; }
function noteWrong(ip) { const now = Date.now(); if (wrongTries.size > 5000) wrongTries.clear(); const t = wrongTries.get(ip); if (!t || t.until <= now) wrongTries.set(ip, { count: 1, until: now + 600000 }); else t.count++; }

/* ---------- GitHub storage ---------- */
function gh(method, path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(GITHUB_API + path);
    const data = body ? JSON.stringify(body) : null;
    const lib = url.protocol === 'http:' ? http : https;
    const req = lib.request({ method, hostname: url.hostname, port: url.port || undefined, path: url.pathname + url.search, headers: {
      'Authorization': 'Bearer ' + githubToken(), 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'fulton-conferences', ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c));
      res.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let json = null; try { json = JSON.parse(text); } catch (e) {} resolve({ status: res.statusCode, json, text }); });
      res.on('error', reject);
    });
    req.setTimeout(60000, () => req.destroy(new Error('GitHub did not answer in time')));
    req.on('error', reject);
    req.end(data || undefined);
  });
}
const store = { ready: false, error: '', branch: 'main', recs: { children: new Map(), conferences: new Map(), settings: new Map() }, originals: new Map(), loadedAt: 0, saveError: '' };
const KEY_NO_WRITE = 'GitHub will not let the access key save changes. On GitHub, edit the Conference records token and set Contents to Read and write.';
const KEY_PROBLEM = 'GitHub rejected the access key, so changes cannot be saved. The GitHub token on Render has probably expired. Renew it on GitHub and paste the new one into GITHUB_TOKEN on Render.';
let rev = 0; const changeLog = []; const BOOT_ID = crypto.randomBytes(6).toString('hex');
function noteChange(kind, id) { rev++; changeLog.push({ rev, kind, id }); if (changeLog.length > 5000) changeLog.splice(0, 1000); }

async function loadAll() {
  if (!githubToken()) { store.error = 'No GITHUB_TOKEN is saved on Render. Add it under Environment.'; log(store.error); return; }
  try {
    const repo = await gh('GET', `/repos/${RECORDS_REPO}`);
    if (repo.status === 404) throw new Error(`The records repository ${RECORDS_REPO} was not found, or the GitHub token cannot see it. Check RECORDS_REPO and give the token access to that repository.`);
    if (repo.status === 401) throw new Error('GitHub rejected the token. Make a new fine-grained token with Contents read and write on the records repository.');
    if (repo.status !== 200) throw new Error('GitHub answered ' + repo.status + ' when opening the records repository.');
    store.branch = repo.json.default_branch || 'main';
    const tree = await gh('GET', `/repos/${RECORDS_REPO}/git/trees/${encodeURIComponent(store.branch)}?recursive=1`);
    if (tree.status === 409) { store.ready = true; store.loadedAt = Date.now(); return; }   // empty repository
    if (tree.status !== 200) throw new Error('GitHub answered ' + tree.status + ' when listing records.');
    const files = (tree.json.tree || []).filter(t => t.type === 'blob');
    const jobs = [];
    for (const f of files) {
      const m = f.path.match(/^(children|conferences|settings)\/([^/]+)\.json$/);
      if (m) jobs.push({ kind: m[1], id: m[2], path: f.path, sha: f.sha });
      const o = f.path.match(/^originals\/([^/]+)$/);
      if (o) store.originals.set(o[1], { path: f.path, sha: f.sha, size: f.size });
    }
    let i = 0;
    const worker = async () => {
      while (i < jobs.length) {
        const j = jobs[i++];
        const b = await gh('GET', `/repos/${RECORDS_REPO}/git/blobs/${j.sha}`);
        if (b.status !== 200) throw new Error('GitHub answered ' + b.status + ' when reading ' + j.path);
        try { const doc = JSON.parse(Buffer.from(b.json.content, 'base64').toString('utf8')); store.recs[j.kind].set(j.id, { doc, sha: j.sha, path: j.path }); }
        catch (e) { log('Skipped unreadable record', j.path); }
      }
    };
    await Promise.all(Array.from({ length: 8 }, worker));
    store.ready = true; store.error = ''; store.loadedAt = Date.now();
    log(`Loaded ${store.recs.children.size} children, ${store.recs.conferences.size} conferences, ${store.originals.size} original files`);
  } catch (e) { store.error = e.message; log('Could not load records.', e.message); }
}

// Saving to GitHub. Each file is saved by one chain at a time, and quick edits are gathered.
const chains = new Map(); const timers = new Map(); const dirtyPaths = new Map();
function scheduleSave(kind, id) {
  const path = `${kind}/${id}.json`; dirtyPaths.set(path, { kind, id });
  clearTimeout(timers.get(path));
  timers.set(path, setTimeout(() => flushPath(path), FLUSH_DELAY_MS));
}
function flushPath(path) {
  clearTimeout(timers.get(path)); timers.delete(path);
  const item = dirtyPaths.get(path); if (!item) return chains.get(path) || Promise.resolve();
  dirtyPaths.delete(path);
  const run = (chains.get(path) || Promise.resolve()).then(() => writeFile(item.kind, item.id)).catch(e => { log('Save failed', path, e.message); dirtyPaths.set(path, item); timers.set(path, setTimeout(() => flushPath(path), 30000)); });
  chains.set(path, run);
  return run;
}
async function flushEverything() { await Promise.all([...dirtyPaths.keys()].map(flushPath)); await Promise.all([...chains.values()]); }
async function currentSha(path) { const r = await gh('GET', `/repos/${RECORDS_REPO}/contents/${path}?ref=${encodeURIComponent(store.branch)}`); return r.status === 200 ? r.json.sha : null; }
async function writeFile(kind, id) {
  const rec = store.recs[kind].get(id); const path = `${kind}/${id}.json`;
  for (let attempt = 0; attempt < 3; attempt++) {
    let r;
    if (!rec || rec.deleted) {
      const shaNow = (rec && rec.sha) || await currentSha(path);
      if (!shaNow) { store.recs[kind].delete(id); return; }
      r = await gh('DELETE', `/repos/${RECORDS_REPO}/contents/${path}`, { message: `Remove ${kind} ${id}`, sha: shaNow, branch: store.branch });
      if (r.status === 200 || r.status === 404) { store.recs[kind].delete(id); return; }
    } else {
      const content = Buffer.from(JSON.stringify(rec.doc, null, 2) + '\n', 'utf8').toString('base64');
      const by = rec.doc.updatedByName ? ` by ${rec.doc.updatedByName}` : '';
      r = await gh('PUT', `/repos/${RECORDS_REPO}/contents/${path}`, { message: `Update ${kind} ${id}${by}`, content, branch: store.branch, ...(rec.sha ? { sha: rec.sha } : {}) });
      if (r.status === 200 || r.status === 201) { rec.sha = r.json.content.sha; store.saveError = ''; return; }
    }
    if (r.status === 409 || r.status === 422) { const s = await currentSha(path); if (rec) rec.sha = s || undefined; continue; }   // changed on GitHub directly, keep the app's copy
    if (r.status === 401) { store.saveError = KEY_PROBLEM; log('GitHub rejected the token'); }
    if (r.status === 403) { store.saveError = KEY_NO_WRITE; log('GitHub key cannot write'); }
    throw new Error('GitHub answered ' + r.status + ' ' + (r.json && r.json.message || ''));
  }
  throw new Error('GitHub kept refusing the save');
}

function deepMerge(target, patch) {
  for (const [k, v] of Object.entries(patch || {})) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (v && typeof v === 'object' && v.__delete__ === true) { delete target[k]; continue; }
    if (v && typeof v === 'object' && !Array.isArray(v)) { if (!target[k] || typeof target[k] !== 'object' || Array.isArray(target[k])) target[k] = {}; deepMerge(target[k], v); }
    else target[k] = v;
  }
  return target;
}

/* ---------- Anthropic ---------- */
const QUICK_MODELS = [process.env.ANTHROPIC_MODEL, 'claude-haiku-5-5', 'claude-haiku-4-5-20251001', 'claude-sonnet-5-5'].map(m => (m || '').trim()).filter((m, i, a) => m && a.indexOf(m) === i);
const CAREFUL_MODELS = [process.env.ANTHROPIC_CAREFUL_MODEL, 'claude-sonnet-5-5', 'claude-sonnet-4-6', 'claude-opus-4-5'].map(m => (m || '').trim()).filter((m, i, a) => m && a.indexOf(m) === i);
const MODEL_SETTINGS = { 'claude-haiku-5-5': { max_tokens: 8000, output_config: { effort: 'low' } } };
const modelAt = { quick: 0, careful: 0 };
function postAnthropic(payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const lib = ANTHROPIC_BASE.protocol === 'http:' ? http : https;
    const req = lib.request({ hostname: ANTHROPIC_BASE.hostname, port: ANTHROPIC_BASE.port || undefined, path: '/v1/messages', method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), 'x-api-key': anthropicKey(), 'anthropic-version': '2023-06-01' } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') })); res.on('error', reject);
    });
    req.setTimeout(UPSTREAM_TIMEOUT_MS, () => req.destroy(new Error('Claude did not answer in time')));
    req.on('error', reject); req.end(body);
  });
}
async function askClaude(content, careful) {
  const lane = careful ? 'careful' : 'quick'; const list = careful ? CAREFUL_MODELS : QUICK_MODELS;
  while (true) {
    const model = list[modelAt[lane]];
    const payload = Object.assign({ model, max_tokens: 8000, messages: [{ role: 'user', content }] }, MODEL_SETTINGS[model] || {});
    const r = await postAnthropic(payload);
    let retired = false; try { retired = r.status === 404 && JSON.parse(r.text).error.type === 'not_found_error'; } catch (e) {}
    if (retired && modelAt[lane] < list.length - 1) { log('Model ' + model + ' is not available, switching'); modelAt[lane]++; continue; }
    return r;
  }
}

/* ---------- HTTP ---------- */
const ALLOWED_ORIGINS = ['https://renee-creator.github.io'].concat(String(process.env.ALLOWED_ORIGINS || '').split(',')).map(s => s.trim().replace(/\/+$/, '').toLowerCase()).filter(Boolean);
function corsFor(req) {
  const o = String(req.headers.origin || '').replace(/\/+$/, '').toLowerCase();
  return ALLOWED_ORIGINS.includes(o) ? { 'Access-Control-Allow-Origin': req.headers.origin, 'Vary': 'Origin', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Max-Age': '86400' } : {};
}
function send(req, res, status, headers, body) {
  try { if (res.headersSent) { res.end(); return; } res.writeHead(status, Object.assign({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }, corsFor(req), headers)); res.end(body); }
  catch (e) { log('Could not send', e.message); }
}
function json(req, res, status, obj) { send(req, res, status, { 'Content-Type': 'application/json; charset=utf-8' }, JSON.stringify(obj)); }
function err(req, res, status, message) { json(req, res, status, { error: message }); }
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => { size += c.length; if (size > MAX_BODY_BYTES) { reject(new Error('too_big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch (e) { reject(new Error('bad_json')); } });
    req.on('error', reject);
  });
}
function snapshot() {
  const out = {}; for (const k of KINDS) { out[k] = {}; for (const [id, r] of store.recs[k]) if (!r.deleted) out[k][id] = r.doc; }
  return out;
}
function statusPage(req, res) {
  const esc = s => String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  const lines = [
    [store.ready, store.ready ? `Records are connected. ${store.recs.children.size} children and ${store.recs.conferences.size} conferences are loaded from ${RECORDS_REPO}.` : (store.error || 'Records are still loading.')],
    [!!anthropicKey(), anthropicKey() ? 'An Anthropic key is saved, so reading forms is available.' : 'No Anthropic key is saved. Add ANTHROPIC_API_KEY under Environment to read forms.'],
    [TEACHERS.length > 0, TEACHERS.length ? `${TEACHERS.length} teacher passcodes are set (${TEACHERS.map(t => esc(t.name)).join(', ')}).` : 'No teacher passcodes are set. Add TEACHER_PASSCODES under Environment, like Hannah=maple garden 42.'],
  ];
  if (store.saveError) lines.unshift([false, store.saveError]);
  if (SKIPPED_PASSCODES) lines.push([false, `${SKIPPED_PASSCODES} passcode entries were ignored. Each must be a passcode of at least 6 characters, or Name=passcode.`]);
  const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Conference server status</title></head><body style="font-family:system-ui,sans-serif;font-size:18px;line-height:1.5;max-width:680px;margin:32px auto;padding:0 16px"><h1 style="font-size:22px">Family Conferences server</h1><p>The server is running.</p>' +
    lines.map(([ok, t]) => `<p style="font-weight:600;color:${ok ? '#1a7f37' : '#b42318'}">${ok ? 'WORKING.' : 'NEEDS ATTENTION.'} ${t}</p>`).join('') +
    `<p style="color:#555;font-size:15px">Reading model ${esc(QUICK_MODELS[modelAt.quick])}. Careful reading model ${esc(CAREFUL_MODELS[modelAt.careful])}.</p></body></html>`;
  send(req, res, 200, { 'Content-Type': 'text/html; charset=utf-8' }, html);
}

async function handle(req, res) {
  const url = new URL(req.url || '/', 'http://x'); const path = url.pathname;
  if (req.method === 'OPTIONS') { send(req, res, 204, {}, undefined); return; }
  if (req.method === 'GET' && (path === '/' || path === '/status')) { statusPage(req, res); return; }
  if (req.method === 'GET' && path === '/health') { json(req, res, 200, { ok: true, ready: store.ready, error: store.error || undefined, saveError: store.saveError || undefined, bootId: BOOT_ID }); return; }

  // original form files are opened in an img or a new tab, which cannot send a header, so the session rides in the address
  if (req.method === 'GET' && path.startsWith('/original/')) {
    if (!checkSession(url.searchParams.get('t') || '')) { send(req, res, 403, { 'Content-Type': 'text/plain' }, 'Sign in to the conference app first.'); return; }
    const id = decodeURIComponent(path.slice(10)); const o = store.originals.get(id);
    if (!o || !ID_RE.test(id)) { send(req, res, 404, { 'Content-Type': 'text/plain' }, 'Not found'); return; }
    const b = await gh('GET', `/repos/${RECORDS_REPO}/git/blobs/${o.sha}`);
    if (b.status !== 200) { send(req, res, 502, { 'Content-Type': 'text/plain' }, 'Could not load the file from GitHub.'); return; }
    const ext = id.split('.').pop().toLowerCase();
    const type = { pdf: 'application/pdf', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp' }[ext] || 'application/octet-stream';
    send(req, res, 200, { 'Content-Type': type, 'Cache-Control': 'private, max-age=3600' }, Buffer.from(b.json.content, 'base64'));
    return;
  }
  if (req.method !== 'POST') { err(req, res, 405, 'Not allowed'); return; }
  const origin = String(req.headers.origin || '').replace(/\/+$/, '').toLowerCase();
  if (!ALLOWED_ORIGINS.includes(origin)) { req.resume(); err(req, res, 403, 'This website is not allowed to use the conference server. Origin received ' + (origin || 'none') + '.'); return; }

  let body;
  try { body = await readBody(req); }
  catch (e) { err(req, res, e.message === 'too_big' ? 413 : 400, e.message === 'too_big' ? 'That upload is too large. Use fewer or smaller pages.' : 'The request could not be read.'); return; }

  if (path === '/login') {
    const ip = who(req);
    if (blocked(ip)) { err(req, res, 429, 'Too many wrong passcodes. Wait ten minutes and try again.'); return; }
    if (!TEACHERS.length) { err(req, res, 503, 'No teacher passcodes are set on the server yet.'); return; }
    const t = matchPasscode(body.passcode);
    if (!t) { noteWrong(ip); err(req, res, 403, 'That passcode is not right. Check with Renee if you have forgotten it.'); return; }
    log('Signed in', t.name);
    json(req, res, 200, { token: makeSession(t.name), name: t.name, teachers: TEACHERS.map(x => x.name) });
    return;
  }

  const me = readSession(req);
  if (!me) { err(req, res, 401, 'Please sign in again.'); return; }
  if (!store.ready) { if (!store.loadedAt) await loadAll(); if (!store.ready) { err(req, res, 503, store.error || 'Records are still loading. Try again in a moment.'); return; } }

  if (path === '/api/data') { json(req, res, 200, { saveError: store.saveError || undefined, bootId: BOOT_ID, rev, me: me.name, teachers: TEACHERS.map(x => x.name), data: snapshot() }); return; }
  if (path === '/api/changes') {
    if (body.bootId !== BOOT_ID || !(body.since >= 0) || (changeLog.length && body.since < changeLog[0].rev - 1)) { json(req, res, 200, { reload: true }); return; }
    const out = {}; for (const c of changeLog) if (c.rev > body.since) { out[c.kind] = out[c.kind] || {}; const r = store.recs[c.kind].get(c.id); out[c.kind][c.id] = r && !r.deleted ? r.doc : null; }
    json(req, res, 200, { bootId: BOOT_ID, rev, changes: out, saveError: store.saveError || undefined }); return;
  }
  if (path === '/api/write') {
    if (store.saveError) { err(req, res, 503, store.saveError + ' Your last change was not saved, so keep a copy of it.'); return; }
    const { op, kind, id } = body;
    if (!KINDS.includes(kind) || typeof id !== 'string' || !ID_RE.test(id)) { err(req, res, 400, 'That record name is not valid.'); return; }
    const map = store.recs[kind]; const cur = map.get(id);
    if (op === 'set') { if (!body.data || typeof body.data !== 'object') { err(req, res, 400, 'Missing data'); return; } map.set(id, { doc: Object.assign({}, body.data, { updatedByName: me.name }), sha: cur && cur.sha, path: `${kind}/${id}.json` }); }
    else if (op === 'update') { if (!cur || cur.deleted) { err(req, res, 404, 'That record no longer exists. It may have been deleted by someone else.'); return; } deepMerge(cur.doc, body.patch || {}); cur.doc.updatedByName = me.name; }
    else if (op === 'delete') { if (cur) cur.deleted = true; else { json(req, res, 200, { ok: true, rev }); return; } }
    else { err(req, res, 400, 'Unknown change'); return; }
    noteChange(kind, id); scheduleSave(kind, id);
    const r = map.get(id);
    json(req, res, 200, { ok: true, rev, doc: r && !r.deleted ? r.doc : null }); return;
  }
  if (path === '/api/save-now') { try { await flushEverything(); json(req, res, 200, { ok: true }); } catch (e) { err(req, res, 502, 'Saving to GitHub failed. ' + e.message); } return; }
  if (path === '/api/original') {
    const name = String(body.name || 'file').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').slice(-60);
    const ext = (name.match(/\.(pdf|jpe?g|png|webp)$/) || [])[1];
    if (!ext || typeof body.data !== 'string') { err(req, res, 400, 'Only PDF, JPEG, PNG and WebP files can be kept as originals.'); return; }
    const buf = Buffer.from(body.data, 'base64');
    if (buf.length > 20 * 1024 * 1024) { err(req, res, 413, 'That file is larger than 20 MB.'); return; }
    const id = crypto.randomBytes(6).toString('hex') + '-' + name.replace(/^[^a-z0-9]+/, '');
    const r = await gh('PUT', `/repos/${RECORDS_REPO}/contents/originals/${id}`, { message: `Add original form by ${me.name}`, content: buf.toString('base64'), branch: store.branch });
    if (r.status === 401 || r.status === 403) { store.saveError = r.status === 401 ? KEY_PROBLEM : KEY_NO_WRITE; err(req, res, 503, store.saveError); return; }
    if (r.status !== 201 && r.status !== 200) { err(req, res, 502, 'GitHub would not store the file. ' + ((r.json && r.json.message) || r.status)); return; }
    store.originals.set(id, { path: `originals/${id}`, sha: r.json.content.sha, size: buf.length });
    json(req, res, 200, { id, sizeBytes: buf.length }); return;
  }
  if (path === '/api/read') {
    if (!anthropicKey()) { err(req, res, 503, 'Reading forms is not set up. Add the Anthropic key on Render.'); return; }
    const content = body.content;
    if (!Array.isArray(content) || !content.length || content.length > 12) { err(req, res, 400, 'Nothing to read'); return; }
    const okBlock = b => b && ((b.type === 'text' && typeof b.text === 'string') || (b.type === 'image' && b.source && b.source.type === 'base64' && /^image\/(jpeg|png|webp|gif)$/.test(b.source.media_type)));
    if (!content.every(okBlock)) { err(req, res, 400, 'That upload could not be sent to Claude.'); return; }
    try {
      const r = await askClaude(content, !!body.careful);
      if (r.status !== 200) { log('Claude answered', r.status, r.text.slice(0, 300)); let m = ''; try { m = JSON.parse(r.text).error.message; } catch (e) {} err(req, res, r.status === 429 || r.status === 529 ? 429 : 502, r.status === 429 || r.status === 529 ? 'Claude is busy. Wait a minute and try again.' : 'Claude could not read this. ' + m); return; }
      const msg = JSON.parse(r.text);
      const text = (msg.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
      log('Form read for', me.name, msg.model, msg.usage ? `${msg.usage.input_tokens} in, ${msg.usage.output_tokens} out` : '');
      json(req, res, 200, { text, model: msg.model, truncated: msg.stop_reason === 'max_tokens' });
    } catch (e) { err(req, res, 502, 'Could not reach Claude. ' + e.message); }
    return;
  }
  err(req, res, 404, 'Not found');
}

const server = http.createServer((req, res) => { handle(req, res).catch(e => { log('Request error', e && e.stack); err(req, res, 500, 'Server error. ' + (e && e.message)); }); });
server.on('clientError', (e, socket) => { try { socket.destroy(); } catch (x) {} });
process.on('uncaughtException', e => log('Unexpected error, server kept running', e && e.stack));
process.on('unhandledRejection', e => log('Unexpected rejection, server kept running', e));
// Render stops the server when it sleeps or redeploys. Save anything waiting first.
let stopping = false;
async function stop(sig) { if (stopping) return; stopping = true; log('Stopping on', sig, 'saving waiting changes'); try { await Promise.race([flushEverything(), new Promise(r => setTimeout(r, 25000))]); } catch (e) {} process.exit(0); }
process.on('SIGTERM', () => stop('SIGTERM')); process.on('SIGINT', () => stop('SIGINT'));

server.listen(PORT, () => {
  log('Conference server on port', PORT, 'records in', RECORDS_REPO);
  log(TEACHERS.length + ' teacher passcodes set');
  log('GitHub key ' + (githubToken() ? 'saved' : 'MISSING') + ', Anthropic key ' + (anthropicKey() ? 'saved' : 'MISSING'));
  loadAll();
});
module.exports = { deepMerge, checkSession, makeSession };
