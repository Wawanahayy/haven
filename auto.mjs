#!/usr/bin/env node
/**
 * auto.mjs — SIWE login + daily checkin (multi akun)
 *
 * .env:
 *   REFERRAL_CODE=xxxxxxx   (opsional, default: c28afdcb)
 *   DEBUG=1                 (opsional)
 *
 * Private key:
 *   privatekey.txt  → 1 line 1 akun
 *     contoh:
 *       0xabc123...
 *       abc456...   (boleh tanpa 0x, nanti otomatis diprefix)
 *
 * Dep:
 *   npm install undici ethers dotenv
 */

import 'dotenv/config';
import fs from 'node:fs';
import { request } from 'undici';
import { Wallet } from 'ethers';

/* ========= BASIC CONFIG ========= */

const BASE_URL        = 'https://camphaven.xyz';
const GRAPHQL_URL     = 'https://gql3.absinthe.network/v1/graphql';
const POINT_SOURCE_ID = '9ac10efc-fd64-4db8-82bd-29b083a1a04b'; // daily checkin point_source_id
const REFERRAL_CODE   = process.env.REFERRAL_CODE || 'c28afdcb';
const CHAIN_ID        = 1;
const CONNECTOR_TAG   = 'connector://io.rabby';
const CALLBACK_PATH   = '/home';

const DEBUG = String(process.env.DEBUG || '').trim() === '1';

/**
 * Cookie awal dari pattern cURL:
 *  client-season, domain, callback-url, redirect-pathname
 */
const INITIAL_COOKIE_JAR = {
  'client-season': 'd2ct-npic',
  'domain': 'https%3A%2F%2Fcamphaven.xyz',
  '__Secure-authjs.callback-url': 'https%3A%2F%2Fboost.absinthe.network',
  'redirect-pathname': '%2Fholders',
};

// cookieJar akan di-reset per akun
let cookieJar = { ...INITIAL_COOKIE_JAR };

/* ========= LOG HELPERS ========= */

function dlog(...args) {
  if (DEBUG) console.log('[DEBUG]', ...args);
}

/* ========= COOKIE HELPERS ========= */

function parseSetCookie(setCookieHeaders = []) {
  const jar = {};
  for (const header of setCookieHeaders) {
    if (!header) continue;
    const [pair] = header.split(';');
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    const name = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    if (!name) continue;
    jar[name] = value;
  }
  return jar;
}

function mergeCookieJars(...jars) {
  return Object.assign({}, ...jars);
}

function cookieJarToHeader(jar) {
  return Object.entries(jar)
    .map(([k, v]) => `${k}=${v}`)
    .join('; ');
}

/* ========= HTTP HELPER ========= */

async function httpJson(method, url, { headers = {}, body } = {}) {
  dlog('HTTP', method, url);
  const res = await request(url, {
    method,
    headers: {
      accept: 'application/json, text/plain, */*',
      'user-agent': 'camp-auto-bot/1.0 (+node)',
      cookie: cookieJarToHeader(cookieJar),
      ...headers,
    },
    body,
  });

  const setCookie =
    res.headers['set-cookie'] || res.headers['set-cookie'.toLowerCase()];
  const setCookieArr = Array.isArray(setCookie)
    ? setCookie
    : setCookie
    ? [setCookie]
    : [];
  const newCookies = parseSetCookie(setCookieArr);
  cookieJar = mergeCookieJars(cookieJar, newCookies);

  const text = await res.body.text();
  let json;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  dlog('HTTP RES', res.statusCode, text);
  return { status: res.statusCode, json, text };
}

/* ========= SIWE MESSAGE BUILDER ========= */

function buildSiweMessage({ domain, address, uri, chainId, nonce, issuedAt }) {
  const lines = [
    `${domain} wants you to sign in with your Ethereum account:`,
    `${address}`,
    '',
    'Please sign with your account',
    '',
    `URI: ${uri}`,
    'Version: 1',
    `Chain ID: ${chainId}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
    'Resources:',
    `- ${CONNECTOR_TAG}`,
  ];

  return lines.join('\n');
}

/* ========= GRAPHQL HELPERS ========= */

async function gqlRequest({ token, operationName, query, variables }) {
  const payload = JSON.stringify({ operationName, query, variables });

  const resp = await httpJson('POST', GRAPHQL_URL, {
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      origin: BASE_URL,
      referer: `${BASE_URL}/`,
      authorization: `Bearer ${token}`,
    },
    body: payload,
  });

  return resp;
}

async function applyReferralIfPossible({ token, userId }) {
  if (!REFERRAL_CODE) {
    dlog('[REFERRAL] REFERRAL_CODE kosong, skip.');
    return;
  }

  const query = `
    mutation updateReferralCode($applyReferralCodeInput: ApplyReferralCodeInput!) {
      apply_referral_code(referral_code_data: $applyReferralCodeInput) {
        success
        __typename
      }
    }
  `;

  const variables = {
    applyReferralCodeInput: {
      referral_code: REFERRAL_CODE,
      user_id: userId,
    },
  };

  const { status, json, text } = await gqlRequest({
    token,
    operationName: 'updateReferralCode',
    query,
    variables,
  });

  if (status >= 400) {
    console.log('[AUTO] Referral: gagal (HTTP), kemungkinan sudah pernah apply / rule lain.');
    dlog('[REFERRAL] HTTP error:', status, text);
    return;
  }

  if (json && json.errors) {
    console.log('[AUTO] Referral Error: (errors server, Or already bind).');
    dlog('[REFERRAL] GraphQL errors:', json.errors);
    return;
  }

  if (json?.data?.apply_referral_code?.success) {
    console.log('[AUTO] Referral: SUCCESS ✅');
  } else {
    console.log('[AUTO] Referral: respon tidak success (lihat DEBUG untuk detail).');
    dlog('[REFERRAL] Response:', JSON.stringify(json));
  }
}

/* ========= PER-AKUN FLOW ========= */

async function runForPrivateKey(rawPk, idx) {
  console.log('');
  console.log('========================================');
  console.log(`=== AKUN #${idx} — START ===============`);

  // reset cookieJar untuk akun ini
  cookieJar = { ...INITIAL_COOKIE_JAR };

  const pk = rawPk.startsWith('0x') ? rawPk : `0x${rawPk}`;
  const wallet  = new Wallet(pk);
  const address = await wallet.getAddress();
  const domain  = new URL(BASE_URL).host;
  const uri     = BASE_URL;

  console.log('[AUTO] Address    :', address);
  console.log('[AUTO] DEBUG mode :', DEBUG ? 'ON' : 'OFF');

  // 1) GET /api/auth/csrf
  const csrfResp = await httpJson('GET', `${BASE_URL}/api/auth/csrf`, {
    headers: { 'content-type': 'application/json' },
  });

  if (csrfResp.status >= 400) {
    throw new Error('[ERROR] Gagal ambil CSRF.');
  }
  if (!csrfResp.json || !csrfResp.json.csrfToken) {
    throw new Error('[ERROR] Respon CSRF tidak valid.');
  }

  const csrfToken = csrfResp.json.csrfToken;

  // 2) Build & sign SIWE
  const issuedAt    = new Date().toISOString();
  const siweMessage = buildSiweMessage({
    domain,
    address,
    uri,
    chainId: CHAIN_ID,
    nonce: csrfToken,
    issuedAt,
  });

  dlog('SIWE MESSAGE:\n' + siweMessage);

  const signature = await wallet.signMessage(siweMessage);
  dlog('Signature:', signature);

  // 3) POST /api/auth/callback/credentials
  const form = new URLSearchParams();
  form.set('message', siweMessage);
  form.set('redirect', 'false');
  form.set('signature', signature);
  form.set('csrfToken', csrfToken);
  form.set('callbackUrl', `${BASE_URL}${CALLBACK_PATH}`);

  const loginResp = await httpJson(
    'POST',
    `${BASE_URL}/api/auth/callback/credentials?`,
    {
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: BASE_URL,
        referer: `${BASE_URL}/home`,
        'x-auth-return-redirect': '1',
      },
      body: form.toString(),
    }
  );

  if (loginResp.status >= 400) {
    dlog('[LOGIN] Body:', loginResp.text);
    throw new Error('[ERROR] Login SIWE HTTP error.');
  }
  if (
    loginResp.json &&
    typeof loginResp.json.url === 'string' &&
    loginResp.json.url.includes('error=CredentialsSignin')
  ) {
    throw new Error('[ERROR] Login SIWE ditolak: CredentialsSignin.');
  }

  console.log('[AUTO] Login SIWE: OK ✅');

  // 4) GET /api/auth/session
  const sessResp = await httpJson(
    'GET',
    `${BASE_URL}/api/auth/session`,
    {
      headers: {
        'content-type': 'application/json',
        referer: `${BASE_URL}/home`,
      },
    }
  );

  if (sessResp.status >= 400) {
    throw new Error('[ERROR] Gagal ambil session.');
  }
  if (!sessResp.json || !sessResp.json.token || !sessResp.json.user) {
    dlog('[SESSION] Body:', sessResp.text);
    throw new Error('[ERROR] Session tidak berisi token/user.');
  }

  const token = sessResp.json.token;
  const user  = sessResp.json.user;

  console.log('[AUTO] Login sebagai user:', user.id);
  dlog('[SESSION] clientSeason:', user.clientSeason);
  dlog('[SESSION] token:', token);

  // 5) Referral (optional)
  await applyReferralIfPossible({ token, userId: user.id });

  // 6) Daily checkin
  console.log('[AUTO] Daily checkin...');
  const gqlQuery = `
    mutation upsertDailyCheckin($object: DailyCheckinInput!) {
      daily_checkin(point_source_data: $object) {
        id
        __typename
      }
    }
  `;

  const gqlVariables = {
    object: {
      user_id: user.id,
      client_season: user.clientSeason,
      point_source_id: POINT_SOURCE_ID,
      status: 'SUCCESS',
    },
  };

  const { status: chkStatus, json: chkJson, text: chkText } = await gqlRequest({
    token,
    operationName: 'upsertDailyCheckin',
    query: gqlQuery,
    variables: gqlVariables,
  });

  if (chkStatus >= 400 || (chkJson && chkJson.errors)) {
    dlog('[CHECKIN] Status:', chkStatus);
    dlog('[CHECKIN] Body  :', chkText);
    throw new Error('[ERROR] Checkin gagal.');
  }

  console.log('[AUTO] Daily checkin: SUCCESS ✅');
  console.log(`=== AKUN #${idx} — DONE =================`);
}

/* ========= MAIN (MULTI ACCOUNT) ========= */

async function main() {
  console.log('=== CAMPHAVEN AUTO BOT (MULTI AKUN) ===');

  // baca privatekey.txt
  let fileContent;
  try {
    fileContent = fs.readFileSync('privatekey.txt', 'utf8');
  } catch (e) {
    console.error('ERROR: Gagal membaca privatekey.txt. Pastikan file ada di folder yang sama dengan auto.mjs');
    process.exit(1);
  }

  const lines = fileContent
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));

  if (lines.length === 0) {
    console.error('ERROR: privatekey.txt kosong atau hanya berisi komentar.');
    process.exit(1);
  }

  console.log(`[INFO] Ditemukan ${lines.length} akun di privatekey.txt`);

  for (let i = 0; i < lines.length; i++) {
    const rawPk = lines[i];
    try {
      await runForPrivateKey(rawPk, i + 1);
    } catch (err) {
      console.error(`[#${i + 1}] ERROR pada akun ini:`, err.message || err);
      // lanjut ke akun berikutnya
    }
  }

  console.log('');
  console.log('=== ALL DONE ===');
}

main().catch((err) => {
  console.error('[FATAL]', err);
  process.exit(1);
});
