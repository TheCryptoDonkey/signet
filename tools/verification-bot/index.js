/**
 * Signet Verification Bot — reference implementation
 *
 * Checks verifier credentials against public professional registers,
 * caches results in SQLite, and publishes findings to Nostr.
 *
 * Port: 3847 (default)
 * Relay: ws://localhost:7777 (default, override via RELAY_URL env var)
 */

import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import Database from 'better-sqlite3';

import WebSocket from 'ws';
import { webcrypto } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';

const PORT = parseInt(process.env.PORT ?? '3847', 10);
const RELAY_URL = process.env.RELAY_URL ?? 'ws://localhost:7777';
const STALE_THRESHOLD_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Bootstrap verifiers — initial trust anchors for the network.
 * These pubkeys are accepted as confirmed (Method B equivalent)
 * without requiring external professional body confirmation.
 * They are the seed from which the trust network grows.
 */
const BOOTSTRAP_VERIFIERS = [
  '13d50cd10d6645d0c87c61b21308a69c0cbe2422a8acce72641786839d39f7ec', // RenegAid
];
const HOURLY_INTERVAL_MS = 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

const db = new Database('verification-bot.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS verifier_checks (
    pubkey TEXT PRIMARY KEY,
    profession TEXT,
    jurisdiction TEXT,
    licence_number TEXT,
    check_result TEXT,
    check_method TEXT,
    last_checked INTEGER,
    details TEXT
  );

  CREATE TABLE IF NOT EXISTS anomaly_flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    verifier_pubkey TEXT,
    flag_type TEXT,
    description TEXT,
    created_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS bot_keys (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    privkey_hex TEXT NOT NULL,
    pubkey_hex TEXT NOT NULL
  );
`);

// ---------------------------------------------------------------------------
// Bot keypair — generated once and persisted in SQLite
// ---------------------------------------------------------------------------

async function ensureBotKeypair() {
  const row = db.prepare('SELECT privkey_hex, pubkey_hex FROM bot_keys WHERE id = 1').get();
  if (row) return row;

  // Generate a random 32-byte private key and derive secp256k1 x-only pubkey
  const privBytes = webcrypto.getRandomValues(new Uint8Array(32));
  const privkey_hex = bytesToHex(privBytes);
  const pubkey_hex = bytesToHex(schnorr.getPublicKey(privBytes));

  db.prepare('INSERT INTO bot_keys (id, privkey_hex, pubkey_hex) VALUES (1, ?, ?)')
    .run(privkey_hex, pubkey_hex);

  console.log('[bot] Generated new keypair. pubkey:', pubkey_hex);
  return { privkey_hex, pubkey_hex };
}

/**
 * Compute a NIP-01 event ID and sign it with Schnorr (BIP-340).
 */
function signNostrEvent(event, privkeyHex) {
  const encoder = new TextEncoder();
  const serialised = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
  const idBytes = sha256(encoder.encode(serialised));
  event.id = bytesToHex(idBytes);
  event.sig = bytesToHex(schnorr.sign(idBytes, privkeyHex));
  return event;
}

// ---------------------------------------------------------------------------
// Professional register checkers — add new jurisdictions here
// ---------------------------------------------------------------------------

const REGISTRY_CHECKERS = {
  /**
   * UK General Medical Council
   * Checks the GMC medical register for a given licence number.
   */
  async UK_GMC(licenceNumber) {
    const url = `https://www.gmc-uk.org/registration-and-licensing/the-medical-register?query=${encodeURIComponent(licenceNumber)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
    const text = await res.text();
    const found = text.includes(licenceNumber);
    return {
      confirmed: found,
      method: 'registry_api',
      url,
      note: found ? 'Licence number found in GMC register.' : 'Licence number not found in GMC register.',
    };
  },

  /**
   * UK Solicitors Regulation Authority
   */
  async UK_SRA(licenceNumber) {
    const url = `https://www.sra.org.uk/consumers/register/search/?q=${encodeURIComponent(licenceNumber)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
    const text = await res.text();
    const found = text.includes(licenceNumber);
    return {
      confirmed: found,
      method: 'registry_api',
      url,
      note: found ? 'Licence number found in SRA register.' : 'Licence number not found in SRA register.',
    };
  },
};

/**
 * Select the appropriate registry checker for a given profession + jurisdiction.
 * Returns null if no checker is implemented yet.
 */
function resolveChecker(profession, jurisdiction) {
  if (!profession || !jurisdiction) return null;
  const prof = profession.toLowerCase();
  const jur = jurisdiction.toUpperCase();

  if (jur === 'GB' || jur === 'UK') {
    if (prof.includes('doctor') || prof.includes('physician') || prof.includes('medical')) {
      return REGISTRY_CHECKERS.UK_GMC;
    }
    if (prof.includes('solicitor') || prof.includes('lawyer') || prof.includes('legal')) {
      return REGISTRY_CHECKERS.UK_SRA;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Nostr relay helpers
// ---------------------------------------------------------------------------

/**
 * Fetch kind 31000 (NIP-VA) verifier attestation events for a pubkey from the relay.
 * Filters by type tag 'verifier'. Returns the first matching event, or null.
 */
async function fetchVerifierEvent(pubkey) {
  return new Promise((resolve) => {
    let ws;
    const timeout = setTimeout(() => {
      try { ws?.close(); } catch {}
      resolve(null);
    }, 8_000);

    try {
      ws = new WebSocket(RELAY_URL);
    } catch {
      clearTimeout(timeout);
      resolve(null);
      return;
    }

    const subId = `bot-${Date.now()}`;

    ws.on('open', () => {
      ws.send(JSON.stringify(['REQ', subId, { kinds: [31000], authors: [pubkey], '#type': ['verifier'], limit: 1 }]));
    });

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg[0] === 'EVENT' && msg[1] === subId) {
          clearTimeout(timeout);
          ws.close();
          resolve(msg[2]);
        } else if (msg[0] === 'EOSE') {
          clearTimeout(timeout);
          ws.close();
          resolve(null);
        }
      } catch {}
    });

    ws.on('error', () => {
      clearTimeout(timeout);
      resolve(null);
    });
  });
}

/**
 * Publish a Kind 1 result note to the relay.
 * Signs the event with secp256k1 Schnorr (BIP-340) per NIP-01.
 */
async function publishResult(verifierPubkey, result, method, jurisdiction, botKeys) {
  const now = Math.floor(Date.now() / 1000);
  const truncated = verifierPubkey.slice(0, 8) + '…';
  const content = `Verifier ${truncated} ${result === 'confirmed' ? 'confirmed' : 'could not be confirmed'} via ${method === 'registry_api' ? 'registry check' : method} (${jurisdiction ?? 'unknown jurisdiction'}).`;

  const event = {
    kind: 1,
    created_at: now,
    pubkey: botKeys.pubkey_hex,
    tags: [
      ['L', 'signet'],
      ['l', 'verifier-check', 'signet'],
      ['p', verifierPubkey],
      ['result', result],
      ['method', method ?? 'unknown'],
      ['jurisdiction', jurisdiction ?? ''],
      ['checked_at', String(now)],
    ],
    content,
  };

  signNostrEvent(event, botKeys.privkey_hex);

  return new Promise((resolve) => {
    let ws;
    const timeout = setTimeout(() => { try { ws?.close(); } catch {} resolve(false); }, 6_000);
    try { ws = new WebSocket(RELAY_URL); } catch { clearTimeout(timeout); resolve(false); return; }

    ws.on('open', () => {
      ws.send(JSON.stringify(['EVENT', event]));
      clearTimeout(timeout);
      ws.close();
      resolve(true);
    });
    ws.on('error', () => { clearTimeout(timeout); resolve(false); });
  });
}

// ---------------------------------------------------------------------------
// Core check logic
// ---------------------------------------------------------------------------

/**
 * Check a verifier pubkey against public registers.
 * Fetches kind 31000 verifier attestation, extracts credential fields,
 * runs registry check, stores result, and publishes to relay.
 */
async function checkVerifier(pubkey, botKeys) {
  const now = Math.floor(Date.now() / 1000);

  // 1. Fetch verifier event from relay (may be null if relay is unreachable)
  let profession = null, jurisdiction = null, licenceNumber = null;
  const event = await fetchVerifierEvent(pubkey);

  if (event?.tags) {
    for (const tag of event.tags) {
      if (!Array.isArray(tag)) continue;
      if (tag[0] === 'profession') profession = tag[1] ?? null;
      if (tag[0] === 'jurisdiction') jurisdiction = tag[1] ?? null;
      if (tag[0] === 'licence' || tag[0] === 'license') licenceNumber = tag[1] ?? null;
    }
  }

  // Merge with any cached values in case relay was unavailable
  const cached = db.prepare('SELECT * FROM verifier_checks WHERE pubkey = ?').get(pubkey);
  profession = profession ?? cached?.profession ?? null;
  jurisdiction = jurisdiction ?? cached?.jurisdiction ?? null;
  licenceNumber = licenceNumber ?? cached?.licence_number ?? null;

  // 2. Attempt registry check
  let checkResult = 'unconfirmed';
  let checkMethod = 'nip05';
  let details = {};

  const checker = resolveChecker(profession, jurisdiction);
  if (checker && licenceNumber) {
    try {
      const outcome = await checker(licenceNumber);
      checkResult = outcome.confirmed ? 'confirmed' : 'unconfirmed';
      checkMethod = outcome.method;
      details = { url: outcome.url, note: outcome.note };
    } catch (err) {
      checkResult = 'error';
      checkMethod = 'registry_api';
      details = { error: err?.message ?? 'Unknown error' };
    }
  } else if (!profession && !jurisdiction) {
    checkResult = 'error';
    details = { note: 'No kind 31000 verifier attestation found and no cached credential data.' };
  }

  // 3. Persist result
  db.prepare(`
    INSERT INTO verifier_checks (pubkey, profession, jurisdiction, licence_number, check_result, check_method, last_checked, details)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(pubkey) DO UPDATE SET
      profession = excluded.profession,
      jurisdiction = excluded.jurisdiction,
      licence_number = excluded.licence_number,
      check_result = excluded.check_result,
      check_method = excluded.check_method,
      last_checked = excluded.last_checked,
      details = excluded.details
  `).run(pubkey, profession, jurisdiction, licenceNumber, checkResult, checkMethod, now, JSON.stringify(details));

  // 4. Publish result to relay (best-effort)
  await publishResult(pubkey, checkResult, checkMethod, jurisdiction, botKeys).catch(() => {});

  return { pubkey, profession, jurisdiction, licenceNumber, checkResult, checkMethod, details };
}

// ---------------------------------------------------------------------------
// Scheduled background checks (stale entries refreshed every hour)
// ---------------------------------------------------------------------------

async function scheduledCheck(botKeys) {
  const staleTs = Math.floor((Date.now() - STALE_THRESHOLD_MS) / 1000);
  const stale = db.prepare(
    'SELECT pubkey FROM verifier_checks WHERE last_checked < ? OR last_checked IS NULL'
  ).all(staleTs);

  if (stale.length > 0) {
    console.log(`[scheduler] Refreshing ${stale.length} stale verifier(s)…`);
  }

  for (const row of stale) {
    try {
      await checkVerifier(row.pubkey, botKeys);
    } catch (err) {
      console.error(`[scheduler] Error checking ${row.pubkey}:`, err?.message);
    }
  }
}

// ---------------------------------------------------------------------------
// HTTP server (Hono)
// ---------------------------------------------------------------------------

const app = new Hono();

app.get('/', (c) => {
  const total = db.prepare('SELECT COUNT(*) as n FROM verifier_checks').get()?.n ?? 0;
  return c.json({
    service: 'signet-verification-bot',
    version: '0.1.0',
    status: 'ok',
    relay: RELAY_URL,
    total_verifiers_tracked: total,
  });
});

app.get('/status/:pubkey', (c) => {
  const pubkey = c.req.param('pubkey');

  // Bootstrap verifiers are always confirmed (Method B equivalent)
  if (BOOTSTRAP_VERIFIERS.includes(pubkey)) {
    return c.json({
      pubkey,
      confirmed: true,
      method: 'B',
      profession: 'bootstrap',
      jurisdiction: 'global',
      checkedAt: Math.floor(Date.now() / 1000),
      details: { bootstrap: true, note: 'Initial trust anchor for the Signet network' },
    });
  }

  const row = db.prepare('SELECT * FROM verifier_checks WHERE pubkey = ?').get(pubkey);
  if (!row) {
    return c.json({ error: 'Not found. POST /check/:pubkey to trigger a check.' }, 404);
  }
  return c.json({ ...row, details: JSON.parse(row.details ?? '{}') });
});

app.post('/check/:pubkey', async (c) => {
  const pubkey = c.req.param('pubkey');
  if (!/^[0-9a-f]{64}$/.test(pubkey)) {
    return c.json({ error: 'Invalid pubkey — must be 64 hex characters.' }, 400);
  }
  const botKeys = await ensureBotKeypair();
  try {
    const result = await checkVerifier(pubkey, botKeys);
    return c.json(result);
  } catch (err) {
    return c.json({ error: err?.message ?? 'Check failed.' }, 500);
  }
});

app.get('/stats', (c) => {
  const total = db.prepare('SELECT COUNT(*) as n FROM verifier_checks').get()?.n ?? 0;
  const confirmed = db.prepare("SELECT COUNT(*) as n FROM verifier_checks WHERE check_result = 'confirmed'").get()?.n ?? 0;
  const flagged = db.prepare("SELECT COUNT(*) as n FROM anomaly_flags").get()?.n ?? 0;
  const errored = db.prepare("SELECT COUNT(*) as n FROM verifier_checks WHERE check_result = 'error'").get()?.n ?? 0;
  return c.json({ total, confirmed, flagged, errored, unconfirmed: total - confirmed - errored });
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

(async () => {
  const botKeys = await ensureBotKeypair();
  console.log('[bot] Starting Signet Verification Bot on port', PORT);
  console.log('[bot] Relay:', RELAY_URL);

  // Initial stale-check sweep
  await scheduledCheck(botKeys).catch(console.error);

  // Hourly refresh
  setInterval(() => scheduledCheck(botKeys).catch(console.error), HOURLY_INTERVAL_MS);

  serve({ fetch: app.fetch, port: PORT });
  console.log(`[bot] Listening on http://localhost:${PORT}`);
})();
