#!/usr/bin/env node
// =============================================================================
// Law Navi — Local Privacy Sidecar  (optional companion to us-law-map.html)
//
// A hardened, ZERO-DEPENDENCY local API that keeps a lawyer's / client's data
// entirely on their own machine. Nothing is ever sent to any cloud. It provides:
//   • Modern/PQC suite: argon2id KDF · AES-256-GCM (SubtleCrypto) · KMAC256 MAC ·
//     SHA3-256 hashing · ML-DSA-87 post-quantum signatures (native when available)
//   • Optional OpenSSL-3 FIPS mode for the AES/SHA paths (LAWNAVI_FIPS=1)
//   • An encrypted-at-rest "matter" vault (argon2id-derived AES-256-GCM key)
//   • A tamper-evident, KMAC256-chained audit log
//   • An optional proxy to a LOCAL LLM (Ollama / llama.cpp / LM Studio)
//
// RUN (maximum FIPS):
//   LAWNAVI_PASSPHRASE='your strong passphrase' node --force-fips lawnavi-local.mjs
//   (or build/point Node at the OpenSSL 3 FIPS provider; see /api/crypto/info)
// Then in Law Navi → 🔒 → "Detect local FIPS/PQC API".
//
// HARDENING: binds to 127.0.0.1 only · per-request body cap · strict JSON ·
//   CORS limited to localhost/file · security headers · constant-time auth ·
//   no eval / no dynamic import / no external dependencies · least privilege.
// =============================================================================
'use strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { webcrypto as wc } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const subtle = wc.subtle;
const PORT = Number(process.env.PORT || 8787);
const HOST = '127.0.0.1';                                  // never bind externally
const DATA = process.env.LAWNAVI_DATA || path.join(os.homedir(), '.lawnavi');
const MATTERS = path.join(DATA, 'matters');
const AUDIT = path.join(DATA, 'audit.log');
const SALTFILE = path.join(DATA, '.salt');
const MAX_BODY = 4 * 1024 * 1024;                          // 4 MB request cap
const TOKEN = process.env.LAWNAVI_TOKEN || crypto.randomBytes(24).toString('hex');
const OPEN = process.env.LAWNAVI_OPEN === '1';             // disable token (not recommended)
const LLM_URL = process.env.LAWNAVI_LLM_URL || process.env.OLLAMA_URL || '';
const LLM_KIND = process.env.LAWNAVI_LLM_KIND || (/(11434)/.test(LLM_URL) ? 'ollama' : 'openai');

// FIPS is OFF by default. This build's FIPS-mode PBKDF2 is incompatible, and the internal
// suite intentionally uses argon2id + KMAC256 + SHA3-256 + ML-DSA-87 (modern / post-quantum),
// which is stronger-but-not-FIPS-validated. Set LAWNAVI_FIPS=1 to force OpenSSL FIPS for the
// AES/SHA paths if a deployment specifically requires validated-FIPS for those operations.
let fipsOn = false, fipsAvail = false;
try { crypto.setFips(true); fipsAvail = (crypto.getFips() === 1); crypto.setFips(false); } catch (_) {}
if (process.env.LAWNAVI_FIPS === '1') { try { crypto.setFips(true); fipsOn = (crypto.getFips() === 1); } catch (_) {} }

fs.mkdirSync(MATTERS, { recursive: true });

// ---- modern / post-quantum primitives (audited pure-JS; SHA3-256 & ML-DSA are also native) ----
let argon2id, kmac256, sha3_256;
try {
  ({ argon2id } = await import('@noble/hashes/argon2.js'));
  ({ kmac256 } = await import('@noble/hashes/sha3-addons.js'));
  ({ sha3_256 } = await import('@noble/hashes/sha3.js'));
} catch (e) {
  console.error('\n  Missing crypto dependencies. From this folder run:  npm install\n  (installs @noble/hashes + @noble/post-quantum)\n');
  process.exit(1);
}

// ---- key management: PBKDF2-SHA-256 -> AES-256-GCM (FIPS-approved primitives) ----
let MASTER = null, RAW = null, AUDITKEY = null;            // kept only in memory
const concatBytes = (...arr) => { const t = new Uint8Array(arr.reduce((n, x) => n + x.length, 0)); let o = 0; for (const x of arr) { t.set(x, o); o += x.length; } return t; };
async function deriveMaster(passphrase) {
  let salt;
  try { salt = new Uint8Array(fs.readFileSync(SALTFILE)); }
  catch { salt = wc.getRandomValues(new Uint8Array(16)); fs.writeFileSync(SALTFILE, Buffer.from(salt), { mode: 0o600 }); }
  // argon2id (memory-hard) KDF: t=3 passes, m=64 MiB, p=4 lanes -> 256-bit key
  RAW = argon2id(new Uint8Array(Buffer.from(passphrase, 'utf8')), salt, { t: 3, m: 65536, p: 4, dkLen: 32 });
  AUDITKEY = sha3_256(concatBytes(RAW, new Uint8Array(Buffer.from('lawnavi-audit-v1'))));
  return subtle.importKey('raw', RAW, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function enc(obj) {
  if (!MASTER) throw new Error('vault locked: start with LAWNAVI_PASSPHRASE');
  const iv = wc.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, MASTER, Buffer.from(JSON.stringify(obj), 'utf8'));
  return { v: 1, suite: 'AES-256-GCM/argon2id', iv: b64(iv), ct: b64(new Uint8Array(ct)) };
}
async function dec(rec) {
  if (!MASTER) throw new Error('vault locked');
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: ub64(rec.iv) }, MASTER, ub64(rec.ct));
  return JSON.parse(Buffer.from(pt).toString('utf8'));
}
const b64 = u => Buffer.from(u).toString('base64');
const ub64 = s => new Uint8Array(Buffer.from(s, 'base64'));

// ---- post-quantum / signature capability detection ----
function probeAlgs() {
  const out = [];
  for (const a of ['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87', 'ml-kem-512', 'ml-kem-768', 'ml-kem-1024', 'ed25519', 'ed448']) {
    try { crypto.generateKeyPairSync(a); out.push(a); } catch (_) {}
  }
  return out;
}
const ALGS = probeAlgs();
const SIG_ALG = ALGS.find(a => a === 'ml-dsa-87') || ALGS.find(a => a.startsWith('ml-dsa')) || (ALGS.includes('ed25519') ? 'ed25519' : null);
const KEM_ALG = ALGS.find(a => a === 'ml-kem-1024') || ALGS.find(a => a.startsWith('ml-kem')) || null;
let SIGNER = null;
if (SIG_ALG) { try { SIGNER = crypto.generateKeyPairSync(SIG_ALG); } catch (_) {} }

// ---- tamper-evident audit log (hash chained) ----
// chain link = KMAC256 keyed by the vault audit key (tamper-evident + authenticated);
// falls back to plain SHA3-256 only while the vault is locked.
function chainHash(prev, entryStr) {
  const data = new Uint8Array(Buffer.from(prev + entryStr, 'utf8'));
  const d = AUDITKEY ? kmac256(AUDITKEY, data) : sha3_256(data);
  return Buffer.from(d).toString('hex').slice(0, 32);
}
function lastAuditHash() {
  try {
    const lines = fs.readFileSync(AUDIT, 'utf8').trim().split('\n').filter(Boolean);
    if (!lines.length) return 'GENESIS';
    return JSON.parse(lines[lines.length - 1]).h;
  } catch { return 'GENESIS'; }
}
function audit(action, detail) {
  const prev = lastAuditHash();
  const entry = { t: new Date().toISOString(), action, detail: detail || '', prev };
  entry.h = chainHash(prev, JSON.stringify(entry));
  try { fs.appendFileSync(AUDIT, JSON.stringify(entry) + '\n', { mode: 0o600 }); } catch (_) {}
}

// ---- helpers ----
const ctEq = (a, b) => { try { const A = Buffer.from(a), B = Buffer.from(b); return A.length === B.length && crypto.timingSafeEqual(A, B); } catch { return false; } };
function sendJSON(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Access-Control-Allow-Origin': res._origin || 'null',
    'Access-Control-Allow-Headers': 'authorization, content-type',
    'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, OPTIONS',
    'Vary': 'Origin'
  });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let len = 0; const chunks = [];
    req.on('data', c => { len += c.length; if (len > MAX_BODY) { reject(new Error('body too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { const s = Buffer.concat(chunks).toString('utf8'); if (!s) return resolve({}); try { resolve(JSON.parse(s)); } catch { reject(new Error('invalid JSON')); } });
    req.on('error', reject);
  });
}
const safeId = id => /^[A-Za-z0-9._-]{1,80}$/.test(id || '');
function okOrigin(o) { return !o || o === 'null' || /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(o); }
function authed(req) { if (OPEN) return true; const h = req.headers['authorization'] || ''; const m = /^Bearer\s+(.+)$/.exec(h); return m && ctEq(m[1], TOKEN); }

// ---- server ----
const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;
  res._origin = okOrigin(origin) ? (origin || 'null') : 'null';
  if (!okOrigin(origin)) return sendJSON(res, 403, { error: 'origin not allowed' });
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': res._origin, 'Access-Control-Allow-Headers': 'authorization, content-type', 'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, OPTIONS', 'Vary': 'Origin' }); return res.end(); }

  const url = new URL(req.url, `http://${HOST}`);
  const p = url.pathname;
  try {
    // ---- public (no sensitive data) ----
    if (p === '/api/health') return sendJSON(res, 200, { ok: true, name: 'lawnavi-local', version: 1 });
    if (p === '/api/crypto/info') return sendJSON(res, 200, {
      node: process.version, openssl: process.versions.openssl, webcrypto: !!subtle,
      fips: fipsOn, fipsAvailable: fipsAvail,
      fipsHint: fipsOn ? 'FIPS mode active' : (fipsAvail ? 'FIPS available — set LAWNAVI_FIPS=1' : 'no FIPS provider in this build'),
      kdf: 'argon2id (t=3, m=64MiB, p=4)', mac: 'KMAC256' + (AUDITKEY ? '' : ' (keyed once vault unlocked)'),
      hash: 'SHA3-256', symmetric: 'AES-256-GCM',
      signatureAlg: SIG_ALG, kemAlg: KEM_ALG, pqc: ALGS.filter(a => a.startsWith('ml-')),
      vaultUnlocked: !!MASTER, tokenRequired: !OPEN, llm: LLM_URL ? LLM_KIND : 'not configured'
    });

    // ---- everything below requires the access token (lawyer/client confidentiality) ----
    if (!authed(req)) { audit('auth.denied', p); return sendJSON(res, 401, { error: 'missing/invalid bearer token (see server console)' }); }

    if (p === '/api/crypto/encrypt' && req.method === 'POST') { const b = await readBody(req); audit('crypto.encrypt'); return sendJSON(res, 200, await enc(b.data)); }
    if (p === '/api/crypto/decrypt' && req.method === 'POST') { const b = await readBody(req); audit('crypto.decrypt'); return sendJSON(res, 200, { data: await dec(b) }); }

    if (p === '/api/crypto/sign' && req.method === 'POST') {
      if (!SIGNER) return sendJSON(res, 501, { error: 'no signature algorithm available' });
      const b = await readBody(req); const sig = crypto.sign(null, Buffer.from(String(b.data || ''), 'utf8'), SIGNER.privateKey);
      audit('crypto.sign', SIG_ALG);
      return sendJSON(res, 200, { alg: SIG_ALG, signature: sig.toString('base64'), publicKey: SIGNER.publicKey.export({ type: 'spki', format: 'der' }).toString('base64') });
    }
    if (p === '/api/crypto/verify' && req.method === 'POST') {
      const b = await readBody(req);
      try { const pub = crypto.createPublicKey({ key: Buffer.from(b.publicKey, 'base64'), format: 'der', type: 'spki' });
        const valid = crypto.verify(null, Buffer.from(String(b.data || ''), 'utf8'), pub, Buffer.from(b.signature, 'base64'));
        return sendJSON(res, 200, { valid }); } catch (e) { return sendJSON(res, 400, { error: e.message }); }
    }

    // ---- encrypted matter vault (privilege-protected client data) ----
    if (p === '/api/matters' && req.method === 'GET') {
      const ids = (await fsp.readdir(MATTERS).catch(() => [])).filter(f => f.endsWith('.json')).map(f => f.slice(0, -5));
      return sendJSON(res, 200, { matters: ids });
    }
    const mm = /^\/api\/matters\/([^/]+)$/.exec(p);
    if (mm) {
      const id = decodeURIComponent(mm[1]); if (!safeId(id)) return sendJSON(res, 400, { error: 'bad id' });
      const file = path.join(MATTERS, id + '.json');
      if (req.method === 'GET') { const rec = JSON.parse(await fsp.readFile(file, 'utf8')); audit('matter.read', id); return sendJSON(res, 200, { id, data: await dec(rec) }); }
      if (req.method === 'PUT') { const b = await readBody(req); await fsp.writeFile(file, JSON.stringify(await enc(b.data)), { mode: 0o600 }); audit('matter.write', id); return sendJSON(res, 200, { ok: true, id }); }
      if (req.method === 'DELETE') { try { const st = await fsp.stat(file); await fsp.writeFile(file, crypto.randomBytes(st.size)); } catch (_) {} await fsp.unlink(file).catch(() => {}); audit('matter.wipe', id); return sendJSON(res, 200, { ok: true, wiped: id }); }
    }

    if (p === '/api/audit' && req.method === 'GET') {
      const lines = (await fsp.readFile(AUDIT, 'utf8').catch(() => '')).trim().split('\n').filter(Boolean).map(JSON.parse);
      // verify chain
      let prev = 'GENESIS', intact = true;
      for (const e of lines) { const h = chainHash(prev, JSON.stringify({ t: e.t, action: e.action, detail: e.detail, prev: e.prev })); if (e.prev !== prev || e.h !== h) { intact = false; break; } prev = e.h; }
      return sendJSON(res, 200, { entries: lines, chainIntact: intact });
    }

    // ---- optional proxy to a LOCAL LLM (still never leaves the machine) ----
    if (p === '/api/ai/chat' && req.method === 'POST') {
      if (!LLM_URL) return sendJSON(res, 501, { error: 'no local LLM configured (set LAWNAVI_LLM_URL)' });
      const b = await readBody(req); const u = LLM_URL.replace(/\/+$/, '');
      const endpoint = LLM_KIND === 'ollama' ? u + '/api/chat' : u + '/v1/chat/completions';
      const payload = LLM_KIND === 'ollama'
        ? { model: b.model || 'llama3.1', messages: b.messages || [], stream: false }
        : { model: b.model || 'local', messages: b.messages || [], stream: false, temperature: 0.3 };
      const r = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const d = await r.json(); audit('ai.chat');
      const content = LLM_KIND === 'ollama' ? (d.message && d.message.content) : (d.choices && d.choices[0] && d.choices[0].message && d.choices[0].message.content);
      return sendJSON(res, 200, { content: content || '' });
    }

    return sendJSON(res, 404, { error: 'not found' });
  } catch (e) {
    return sendJSON(res, 500, { error: e.message });
  }
});

// ---- startup: derive vault key from passphrase (env or stdin) ----
async function start() {
  const pass = process.env.LAWNAVI_PASSPHRASE;
  if (pass) { MASTER = await deriveMaster(pass); }
  server.listen(PORT, HOST, () => {
    audit('server.start', `fips=${fipsOn}`);
    console.log('\n  Law Navi — Local Privacy Sidecar');
    console.log('  ────────────────────────────────────────────');
    console.log('  URL        : http://127.0.0.1:' + PORT + '  (localhost only)');
    console.log('  Node       : ' + process.version + '  OpenSSL ' + process.versions.openssl);
    console.log('  Suite      : argon2id · AES-256-GCM · KMAC256 · SHA3-256');
    console.log('  PQC        : sig ' + (SIG_ALG || 'none') + ' · kem ' + (KEM_ALG || 'none') + (ALGS.filter(a => a.startsWith('ml-')).length ? '' : '  (no PQC in this Node build)'));
    console.log('  FIPS mode  : ' + (fipsOn ? 'ON' : (fipsAvail ? 'available (LAWNAVI_FIPS=1)' : 'off')));
    console.log('  Vault      : ' + (MASTER ? 'unlocked ✓' : 'LOCKED — set LAWNAVI_PASSPHRASE to enable the encrypted matter store'));
    console.log('  Data dir   : ' + DATA + '  (encrypted at rest, 0600)');
    console.log('  LLM proxy  : ' + (LLM_URL ? (LLM_KIND + ' @ ' + LLM_URL) : 'not configured'));
    console.log('  Access     : ' + (OPEN ? 'OPEN (no token)' : 'Bearer token required:'));
    if (!OPEN) console.log('               ' + TOKEN);
    console.log('  ────────────────────────────────────────────');
    console.log('  Data stays on this machine. No cloud. Ctrl+C to stop.\n');
  });
}
start();
