// Wallet screens (gui-plan P6a): wallet selector + load picker, overview
// balances, receive with a client-side QR code, transaction history, and
// the address book — bitcoin-qt's walletview tabs transposed. Send/fee UI
// is P6b (needs wallet P4).
//
// RPC shapes consumed here are exactly what src/rpc/wallet*.lisp emits;
// every wallet-scoped call rides the /wallet/<name> endpoint (Core
// httprpc's wallet endpoint), so multi-wallet nodes are unambiguous:
//
//   listwallets -> [name…]; listwalletdir -> { wallets: [{ name }…] }.
//   loadwallet [name] -> { name, warnings? } (slow: catches the wallet up
//     to the tip before returning).
//   getbalances -> { mine: { trusted, untrusted_pending, immature, used? },
//     lastprocessedblock: { hash, height } } (amounts are BTC JSON numbers).
//   getwalletinfo -> { walletname, format, txcount, keypoolsize,
//     keypoolsize_hd_internal, private_keys_enabled, avoid_reuse, blank,
//     descriptors, birthtime?, scanning (false | { duration, progress }),
//     lastprocessedblock } — booleans are real JSON booleans (wave 10).
//   getnewaddress [label, address_type] -> address string; the four Core
//     output types are accepted, default bech32 (wallet.h
//     DEFAULT_ADDRESS_TYPE); -12 when that type's keypool is exhausted.
//   getaddressinfo [address] -> { address, ismine, solvable, ischange,
//     hdkeypath?, parent_desc?, desc?, labels, … } (reuse indicators are
//     rendered whenever a `reused` field appears; ours does not emit one
//     yet).
//   listtransactions ['*', count, skip] -> oldest-first page of entries
//     { category: send|receive|generate|immature|orphan, amount (negative
//     for sends), fee? (sends), address?, label?, vout, confirmations,
//     txid, time, abandoned, trusted?, blockhash?/blockheight? … };
//     display order here is newest-first.
//   gettransaction [txid] -> { amount, fee?, confirmations, txid, wtxid,
//     walletconflicts, mempoolconflicts, bip125-replaceable, time,
//     timereceived, details, blockhash?/blockheight?/blocktime?, … }.
//   listlabels [] -> [label…]; getaddressesbylabel [label] ->
//     { address: { purpose } } (-11 when a label just vanished);
//   setlabel [address, label] -> null (purpose: receive when mine, else
//     send — how sending addresses enter the book, like Qt's "New").
//
// Wallet support disabled (mainnet default) surfaces as RPC -32601 on
// every wallet method, exactly like a no-wallet Core build — that renders
// as a "wallet support is disabled" state, never a broken page. No wallet
// loaded is RPC -18 territory; the page never gets there because it
// resolves the wallet list first and shows the load/create empty state.
//
// The mask-values toggle (Qt's privacy mode) blurs every .amt node via a
// container class; the preference lives in sessionStorage like the
// credentials. The pure helpers up top are exported for the node test
// harness (tests/ui/wallet.test.mjs).

import * as rpc from './rpc.js';
import { qrDataUri } from './qr.js';
import {
  fmtInt, fmtBtc, fmtAge, fmtPct, fmtDuration, fmtTimestamp, fmtFeeRate,
  shortHash, shortId,
} from './format.js';
import {
  encryptionState, isEncrypted, STATE_UI, unlockCountdown,
  UNLOCK_TIMEOUTS, DEFAULT_UNLOCK_TIMEOUT, validatePassphrasePair,
  validateTimeout, validateCreate, PASSPHRASE_HINT, ENCRYPT_WARNING,
  ENCRYPT_BACKUP_WARNING, unlockParams, createParams, withUnlocked,
  UnlockCancelled, forgetPassphrase,
} from './wallet-crypt.js';

// --- pure helpers (exported for tests) --------------------------------

export const MASK_KEY = 'bitcoin-lisp.mask-values';
export const WALLET_KEY = 'bitcoin-lisp.wallet';
export const HISTORY_PAGE_SIZE = 25;

// Core's four output types (outputtype.cpp); bech32 is the getnewaddress
// default (wallet.h DEFAULT_ADDRESS_TYPE).
export const ADDRESS_TYPES = ['bech32', 'bech32m', 'p2sh-segwit', 'legacy'];

// The /wallet/<name> endpoint for NAME (hunchentoot url-decodes, so
// encodeURIComponent round-trips any legal wallet name).
export function walletEndpoint(name) {
  return `/wallet/${encodeURIComponent(name)}`;
}

// BIP21 payment URI for the QR code (Qt receiverequestdialog encodes the
// same form; the scheme is "bitcoin:" on every network).
export function bip21Uri(address, label = '') {
  return `bitcoin:${address}${label ? `?label=${encodeURIComponent(label)}` : ''}`;
}

// [method, params] seams for every write/fetch, testable in isolation.
export function loadParams(name) {
  return ['loadwallet', [name]];
}
export function newAddressParams(label, type) {
  return ['getnewaddress', [label || '', type]];
}
export function setLabelParams(address, label) {
  return ['setlabel', [address, label]];
}
// One entry beyond the page probes whether an older page exists.
export function historyParams(page, pageSize = HISTORY_PAGE_SIZE) {
  return ['listtransactions', ['*', pageSize + 1, page * pageSize]];
}

// listtransactions answers oldest-first; the table shows newest-first.
// With the +1 probe entry, the oldest entry is the peek into the next
// page — drop it from display.
export function historyPage(result, pageSize = HISTORY_PAGE_SIZE) {
  const entries = [...(result || [])].reverse(); // newest-first
  const hasMore = entries.length > pageSize;
  return { entries: entries.slice(0, pageSize), hasMore };
}

// Stable identity for a history entry (one tx can contribute both a send
// and a receive entry).
export function entryKey(e) {
  return `${e.txid}:${e.category}:${e.vout ?? ''}`;
}

// Which wallets in the wallet directory are not currently loaded.
export function unloadedWallets(dirResult, loaded) {
  const names = (dirResult?.wallets || []).map((w) => w.name);
  return names.filter((n) => !loaded.includes(n)).sort();
}

export function categoryVariant(category) {
  switch (category) {
    case 'receive': return 'pill-good';
    case 'generate': return 'pill-good';
    case 'send': return 'pill-muted';
    case 'immature': return 'pill-accent';
    case 'orphan': return 'pill-bad';
    default: return 'pill-muted';
  }
}

// --- send: pure helpers (exported for tests) --------------------------

// Confirmation-target choices for the fee control (blocks); 6 is the wallet
// default (Core -txconfirmtarget, DEFAULT_TX_CONFIRM_TARGET = 6).
export const SEND_CONF_TARGETS = [1, 2, 3, 6, 12, 24, 144, 1008];
export const DEFAULT_CONF_TARGET = 6;
export const MAX_MONEY_SATS = 2100000000000000n; // 21e6 BTC (consensus.h)

// The wallet signals RBF by default (Core -walletrbf true); the fee-estimate
// mode tracks it exactly like CWallet::GetMinimumFeeRate — economical while
// signaling replaceability, conservative otherwise — so the estimatesmartfee
// preview reflects the rate the node itself will target for this spend.
export function feeModeForRbf(rbf) {
  return rbf ? 'economical' : 'conservative';
}

// estimatesmartfee is a NODE method (base endpoint): [conf_target, mode].
export function estimateFeeParams(confTarget, rbf) {
  return ['estimatesmartfee', [confTarget, feeModeForRbf(rbf)]];
}

// A BTC amount string -> { ok, value, sats } or { ok:false, reason }. VALUE is
// a canonical decimal string (never a float): the node parses the decimal
// text exactly (AmountFromValue), so we forward text and never let JS float
// noise into a funds amount. Satoshis are exact BigInt for the review total.
export function normalizeAmount(input) {
  const s = String(input ?? '').trim();
  if (s === '') return { ok: false, reason: 'amount is required' };
  if (!/^\d*\.?\d*$/.test(s) || s === '.') {
    return { ok: false, reason: 'amount must be a number' };
  }
  const [whole = '', frac = ''] = s.split('.');
  if (frac.length > 8) return { ok: false, reason: 'at most 8 decimal places' };
  const sats = BigInt(whole || '0') * 100000000n
    + BigInt((frac + '00000000').slice(0, 8));
  if (sats <= 0n) return { ok: false, reason: 'amount must be greater than zero' };
  if (sats > MAX_MONEY_SATS) {
    return { ok: false, reason: 'amount exceeds 21,000,000 BTC' };
  }
  const value = frac.length ? `${whole || '0'}.${frac}` : (whole || '0');
  return { ok: true, value, sats };
}

// Lightweight, network-agnostic destination check: catches empty/whitespace
// and obviously-malformed strings for instant feedback; the node stays the
// authority (decode-address re-validates the checksum before spending).
const BECH32_RE = /^(bc|tb|bcrt)1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,100}$/;
const BASE58_RE = /^[123mn][1-9A-HJ-NP-Za-km-z]{25,39}$/;
export function validateAddress(input) {
  const a = String(input ?? '').trim();
  if (a === '') return { ok: false, reason: 'address is required' };
  if (/\s/.test(a)) return { ok: false, reason: 'address must not contain spaces' };
  if (!BECH32_RE.test(a.toLowerCase()) && !BASE58_RE.test(a)) {
    return { ok: false, reason: 'not a recognized Bitcoin address' };
  }
  return { ok: true, address: a };
}

// Validate every recipient row. Returns { ok, cleaned, errors }: CLEANED is
// [{ address, amount(string), sats(BigInt) }] when OK; ERRORS is
// [{ index, field, reason }] (index -1 = whole form).
export function validateRecipients(recipients) {
  const cleaned = [];
  const errors = [];
  const rows = recipients ?? [];
  if (rows.length === 0) {
    return { ok: false, cleaned,
      errors: [{ index: -1, field: 'form', reason: 'add at least one recipient' }] };
  }
  const seen = new Map();
  rows.forEach((r, i) => {
    const addr = validateAddress(r.address);
    if (!addr.ok) errors.push({ index: i, field: 'address', reason: addr.reason });
    const amt = normalizeAmount(r.amount);
    if (!amt.ok) errors.push({ index: i, field: 'amount', reason: amt.reason });
    if (addr.ok) {
      if (seen.has(addr.address)) {
        errors.push({ index: i, field: 'address', reason: 'duplicate address' });
      } else {
        seen.set(addr.address, i);
      }
    }
    cleaned.push(addr.ok && amt.ok
      ? { address: addr.address, amount: amt.value, sats: amt.sats } : null);
  });
  return {
    ok: errors.length === 0,
    cleaned: errors.length === 0 ? cleaned : [],
    errors,
  };
}

// Build the exact [method, params] for a spend. A single recipient rides
// sendtoaddress (Core's single-payment path); multiple recipients ride send
// with an order-preserving array-of-objects outputs list. Amounts are
// forwarded as decimal strings. Booleans are real JSON booleans — the node's
// request parser promotes a top-level positional `false` to its explicit-
// false sentinel, so RBF-off / SFFO-off transmit losslessly.
export function buildSendCall({ recipients, confTarget, rbf, subtractFee }) {
  const mode = feeModeForRbf(rbf);
  if (recipients.length === 1) {
    const r = recipients[0];
    // sendtoaddress: address, amount, comment, comment_to,
    //   subtractfeefromamount, replaceable, conf_target, estimate_mode
    return ['sendtoaddress',
      [r.address, r.amount, '', '', !!subtractFee, !!rbf, confTarget, mode]];
  }
  // send: outputs, conf_target, estimate_mode, fee_rate, options
  const outputs = recipients.map((r) => ({ [r.address]: r.amount }));
  const options = { replaceable: !!rbf };
  if (subtractFee) options.subtract_fee_from_outputs = recipients.map((_, i) => i);
  return ['send', [outputs, confTarget, mode, null, options]];
}

// Broadcast txid from either RPC's result (sendtoaddress -> bare txid string;
// send -> { txid, complete }).
export function sendResultTxid(result) {
  return typeof result === 'string' ? result : (result?.txid ?? null);
}

// Rough signed-vsize estimate for the fee PREVIEW only (P2WPKH-ish: 11 vB
// overhead + ~68 vB/input + ~31 vB/output incl. one change output). The node
// computes the real size from the selected coins; this only powers the
// "≈ fee" line beside the authoritative feerate.
export function estimateVsize(numOutputs, numInputs = 1) {
  return Math.ceil(11 + numInputs * 68 + (numOutputs + 1) * 31);
}

// Exact BigInt-satoshi -> "N.NNNNNNNN BTC" (no float round-trip).
export function fmtSatsBtc(sats) {
  const neg = sats < 0n;
  const a = neg ? -sats : sats;
  const whole = (a / 100000000n).toString();
  const frac = (a % 100000000n).toString().padStart(8, '0');
  return `${neg ? '-' : ''}${whole}.${frac} BTC`;
}

export function isMasked(storage = globalThis.sessionStorage) {
  return storage.getItem(MASK_KEY) === '1';
}
export function setMasked(on, storage = globalThis.sessionStorage) {
  if (on) storage.setItem(MASK_KEY, '1');
  else storage.removeItem(MASK_KEY);
}

// --- module state ------------------------------------------------------

const TABS = [
  ['overview', 'Overview'],
  ['send', 'Send'],
  ['receive', 'Receive'],
  ['history', 'History'],
  ['addresses', 'Address book'],
  ['security', 'Security'],
];

const state = {
  container: null,
  refs: null,
  tab: 'overview',
  disabled: false,     // wallet support off (-32601)
  wallets: [],         // listwallets
  selected: null,      // active wallet name
  balances: null,
  walletinfo: null,
  chainHeight: null,
  histPage: 0,
  histEntries: [],
  histHasMore: false,
  expandedKey: null,
  txDetails: new Map(), // txid -> gettransaction result
  bookRows: [],         // [{ address, label, purpose, info? }]
  receive: null,        // { address, label, type, uri, info? }
  send: freshSend(),    // send-tab compose model
  secPanelOnClose: null,  // fired when the Security panel closes (see promptUnlock)
  refreshing: false,
};

// A blank send-tab compose model (one empty recipient, wallet defaults).
function freshSend() {
  return {
    recipients: [{ address: '', amount: '' }],
    confTarget: DEFAULT_CONF_TARGET,
    rbf: true,
    sffo: false,
    preview: null,     // { feerate, blocks, errors, vsize, feeSats, rbf, sffo }
    result: null,      // { txid, feeReason } | { error }
    reviewing: false,
    rowRefs: [],       // [{ addr, amount }] live input elements
    cleaned: [],       // validated recipients backing the review/confirm
  };
}

export function resetWallet() {
  state.container = null;
  state.refs = null;
  state.tab = 'overview';
  state.disabled = false;
  state.wallets = [];
  state.selected = null;
  state.balances = null;
  state.walletinfo = null;
  state.chainHeight = null;
  state.histPage = 0;
  state.histEntries = [];
  state.histHasMore = false;
  state.expandedKey = null;
  state.txDetails = new Map();
  state.bookRows = [];
  state.receive = null;
  state.send = freshSend();
  state.refreshing = false;
}

function endpoint() {
  return walletEndpoint(state.selected);
}

// --- DOM helpers (textContent only for dynamic data — no injection) ---

function el(tag, className = '', text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function link(href, text, className = 'xlink') {
  const a = el('a', className, text);
  a.href = href;
  return a;
}

// An amount span the mask toggle blurs (never mirrored into title attrs —
// masked means hidden).
function amt(text) {
  return el('span', 'amt mono', text);
}

function kvRow(label, ...values) {
  const row = el('div');
  row.appendChild(el('dt', '', label));
  const dd = el('dd', 'mono');
  dd.append(...values);
  row.appendChild(dd);
  return row;
}

function pill(text, variant = '') {
  return el('span', `pill ${variant}`, text);
}

async function copyToClipboard(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = 'copied';
  } catch {
    btn.textContent = 'copy failed';
  }
  setTimeout(() => { btn.textContent = 'copy'; }, 1200);
}

function copyable(full, display = full) {
  const wrap = el('span', 'copyable');
  const value = el('span', 'mono', display);
  if (display !== full) value.title = full;
  const btn = el('button', 'copy-btn', 'copy');
  btn.type = 'button';
  btn.title = 'Copy the full value';
  btn.addEventListener('click', () => copyToClipboard(full, btn));
  wrap.append(value, btn);
  return wrap;
}

function rpcErrorMessage(e) {
  if (e instanceof rpc.RpcError) return `${e.message} (RPC error ${e.code})`;
  if (e instanceof rpc.AuthError) return `Session ended: ${e.message}`;
  // A dismissed unlock prompt is a user choice, not a failure to reach the
  // node — it carries its own sentence and needs no "Could not reach" frame.
  if (e instanceof UnlockCancelled) return e.message;
  return `Could not reach the node: ${e.message}`;
}

// Same two-step armed confirm as the peers page.
function armedButton(label, confirmLabel, run, className = 'btn') {
  const btn = el('button', className, label);
  btn.type = 'button';
  let armed = false;
  let timer = null;
  const disarm = () => {
    armed = false;
    clearTimeout(timer);
    btn.textContent = label;
    btn.classList.remove('armed');
  };
  btn.addEventListener('click', async () => {
    if (!armed) {
      armed = true;
      btn.textContent = confirmLabel;
      btn.classList.add('armed');
      timer = setTimeout(disarm, 4000);
      return;
    }
    clearTimeout(timer);
    btn.disabled = true;
    btn.textContent = 'working…';
    try {
      await run();
    } finally {
      btn.disabled = false;
      disarm();
    }
  });
  return btn;
}

// --- skeleton -----------------------------------------------------------

// Build once per login/container; refresh() fills it. Returns the initial
// refresh's promise (awaited by tests, not by app.js).
export function show(container, tab) {
  if (state.container !== container || !state.refs) {
    state.container = container;
    buildSkeleton(container);
  }
  const wanted = TABS.some(([name]) => name === tab) ? tab : 'overview';
  if (wanted !== state.tab) {
    state.tab = wanted;
    renderTabStrip();
    renderVisibility();
  }
  return refresh();
}

function buildSkeleton(container) {
  const refs = {};

  // Header card: wallet selector + load picker + mask toggle + tab strip.
  const head = el('section', 'card card-full');
  head.setAttribute('aria-label', 'Wallet');
  const headRow = el('div', 'wallet-head');
  headRow.appendChild(el('h2', 'card-title', 'Wallet'));

  refs.select = el('select', 'wallet-select');
  refs.select.setAttribute('aria-label', 'Active wallet');
  refs.select.addEventListener('change', () => selectWallet(refs.select.value));
  refs.watchPill = pill('watch-only', 'pill-muted');
  refs.watchPill.hidden = true;

  refs.maskBtn = el('button', 'btn', '');
  refs.maskBtn.type = 'button';
  refs.maskBtn.addEventListener('click', () => {
    setMasked(!isMasked());
    applyMask();
  });

  headRow.append(refs.select, refs.watchPill, refs.maskBtn);
  head.appendChild(headRow);

  // Load picker (hidden while every directory wallet is loaded).
  refs.loadRow = el('div', 'wallet-load');
  refs.loadSelect = el('select');
  refs.loadSelect.setAttribute('aria-label', 'Wallet to load');
  refs.loadError = el('p', 'error-text');
  refs.loadError.hidden = true;
  refs.loadBtn = armedButton('load', 'confirm load?', async () => {
    const name = refs.loadSelect.value;
    if (!name) return;
    refs.loadError.hidden = true;
    try {
      await rpc.call(...loadParams(name));
      await selectWallet(name);
    } catch (e) {
      refs.loadError.textContent = rpcErrorMessage(e);
      refs.loadError.hidden = false;
      await refresh();
    }
  });
  refs.loadRow.append(el('span', 'muted', 'load from wallet directory:'),
    refs.loadSelect, refs.loadBtn);
  refs.loadRow.hidden = true;
  head.append(refs.loadRow, refs.loadError);

  refs.tabstrip = el('nav', 'tabstrip');
  refs.tabstrip.setAttribute('aria-label', 'Wallet sections');
  for (const [name, label] of TABS) {
    const a = link(`#/wallet${name === 'overview' ? '' : `/${name}`}`, label, 'tab-item');
    a.dataset.tab = name;
    refs.tabstrip.appendChild(a);
  }
  head.appendChild(refs.tabstrip);

  // Disabled / empty states.
  refs.disabledCard = el('section', 'card card-full');
  refs.disabledCard.setAttribute('aria-label', 'Wallet disabled');
  refs.disabledCard.appendChild(el('h2', 'card-title', 'Wallet'));
  refs.disabledCard.appendChild(el('p', 'wallet-state',
    'Wallet support is disabled on this network.'));
  refs.disabledCard.appendChild(el('p', 'muted',
    'The node runs without a wallet (mainnet default). Start it with the '
    + '-wallet config flag to enable wallet support; wallet RPCs answer '
    + '"method not found" until then, exactly like a no-wallet Core build.'));
  refs.disabledCard.hidden = true;

  refs.emptyCard = el('section', 'card card-full');
  refs.emptyCard.setAttribute('aria-label', 'No wallet loaded');
  refs.emptyCard.appendChild(el('h2', 'card-title', 'No wallet loaded'));
  refs.emptyCard.appendChild(el('p', 'wallet-state', 'This node has wallet '
    + 'support, but no wallet is loaded.'));
  refs.emptyHint = el('p', 'muted',
    'Load an existing wallet from the picker above, or create one from the '
    + 'Console: createwallet "name" true (watch-only descriptor wallet — '
    + 'import descriptors afterwards with importdescriptors).');
  refs.emptyCard.appendChild(refs.emptyHint);
  refs.emptyCard.hidden = true;

  // Overview: balances + wallet facts.
  refs.balancesCard = el('section', 'card wallet-card');
  refs.balancesCard.setAttribute('aria-label', 'Balances');
  refs.balancesCard.appendChild(el('h2', 'card-title', 'Balances'));
  refs.balTotal = el('div', 'stat');
  refs.balancesCard.appendChild(refs.balTotal);
  refs.balKv = el('dl', 'kv');
  refs.balancesCard.appendChild(refs.balKv);

  refs.infoCard = el('section', 'card wallet-card');
  refs.infoCard.setAttribute('aria-label', 'Wallet info');
  refs.infoCard.appendChild(el('h2', 'card-title', 'Wallet info'));
  refs.infoKv = el('dl', 'kv');
  refs.infoCard.appendChild(refs.infoKv);
  refs.overviewError = el('p', 'error-text');
  refs.overviewError.hidden = true;
  refs.infoCard.appendChild(refs.overviewError);

  // Send: multi-recipient compose + fee control -> review/confirm.
  refs.sendCard = el('section', 'card card-full');
  refs.sendCard.setAttribute('aria-label', 'Send');
  refs.sendCard.appendChild(el('h2', 'card-title', 'Send'));
  const sendForm = el('form', 'send-form');
  refs.sendRecipients = el('div', 'send-recipients');
  sendForm.appendChild(refs.sendRecipients);

  refs.sendAddBtn = el('button', 'btn send-add', '+ add recipient');
  refs.sendAddBtn.type = 'button';
  refs.sendAddBtn.addEventListener('click', () => addRecipient());
  sendForm.appendChild(refs.sendAddBtn);

  const controls = el('div', 'send-controls');
  const ctWrap = el('label', 'send-control');
  ctWrap.appendChild(el('span', 'muted', 'confirm within'));
  refs.sendConfTarget = el('select', 'send-conf-target');
  refs.sendConfTarget.setAttribute('aria-label', 'Confirmation target (blocks)');
  for (const t of SEND_CONF_TARGETS) {
    const opt = el('option', '', `${fmtInt(t)} block${t === 1 ? '' : 's'}`);
    opt.value = String(t);
    refs.sendConfTarget.appendChild(opt);
  }
  refs.sendConfTarget.value = String(DEFAULT_CONF_TARGET);
  ctWrap.appendChild(refs.sendConfTarget);
  controls.appendChild(ctWrap);

  const rbfWrap = el('label', 'send-control');
  refs.sendRbf = el('input');
  refs.sendRbf.type = 'checkbox';
  refs.sendRbf.checked = true;
  refs.sendRbf.setAttribute('aria-label', 'Signal replace-by-fee (BIP125)');
  rbfWrap.append(refs.sendRbf, el('span', '', 'replaceable (RBF)'));
  controls.appendChild(rbfWrap);

  const sffoWrap = el('label', 'send-control');
  refs.sendSffo = el('input');
  refs.sendSffo.type = 'checkbox';
  refs.sendSffo.checked = false;
  refs.sendSffo.setAttribute('aria-label', 'Subtract fee from outputs');
  sffoWrap.append(refs.sendSffo, el('span', '', 'subtract fee from amount(s)'));
  controls.appendChild(sffoWrap);
  sendForm.appendChild(controls);

  refs.sendError = el('p', 'error-text');
  refs.sendError.hidden = true;
  sendForm.appendChild(refs.sendError);

  refs.sendReviewBtn = el('button', 'btn send-review-btn', 'review send');
  refs.sendReviewBtn.type = 'submit';
  sendForm.appendChild(refs.sendReviewBtn);
  sendForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    await onReviewSend();
  });

  refs.sendReview = el('div', 'send-review-wrap');
  refs.sendReview.hidden = true;
  refs.sendResult = el('div', 'send-result-wrap');
  refs.sendResult.hidden = true;
  refs.sendCard.append(sendForm, refs.sendReview, refs.sendResult);

  // Receive.
  refs.receiveCard = el('section', 'card card-full');
  refs.receiveCard.setAttribute('aria-label', 'Receive');
  refs.receiveCard.appendChild(el('h2', 'card-title', 'Receive'));
  const form = el('form', 'receive-form');
  refs.recvLabel = el('input');
  refs.recvLabel.placeholder = 'label (optional)';
  refs.recvLabel.spellcheck = false;
  refs.recvLabel.setAttribute('aria-label', 'Label for the new address');
  refs.recvType = el('select');
  refs.recvType.setAttribute('aria-label', 'Address type');
  for (const t of ADDRESS_TYPES) {
    refs.recvType.appendChild(el('option', '', t));
  }
  refs.recvType.value = 'bech32';
  refs.recvBtn = el('button', 'btn', 'generate new address');
  refs.recvBtn.type = 'submit';
  form.append(refs.recvLabel, refs.recvType, refs.recvBtn);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    await generateAddress();
  });
  refs.receiveError = el('p', 'error-text');
  refs.receiveError.hidden = true;
  refs.receiveResult = el('div', 'receive-result');
  refs.receiveCard.append(form, refs.receiveError, refs.receiveResult);

  // History.
  refs.historyCard = el('section', 'card card-full');
  refs.historyCard.setAttribute('aria-label', 'Transaction history');
  refs.histTitle = el('h2', 'card-title', 'History');
  refs.historyCard.appendChild(refs.histTitle);
  const histWrap = el('div', 'table-wrap');
  const histTable = el('table', 'peers wtx');
  const histHead = el('thead');
  const histHrow = el('tr');
  for (const label of ['category', 'amount', 'conf', 'label', 'address', 'time']) {
    histHrow.appendChild(el('th', '', label));
  }
  histHead.appendChild(histHrow);
  refs.histBody = el('tbody');
  histTable.append(histHead, refs.histBody);
  histWrap.appendChild(histTable);
  refs.histPagerTop = el('div', 'pager');
  refs.histPagerBottom = el('div', 'pager');
  refs.histError = el('p', 'error-text');
  refs.histError.hidden = true;
  refs.historyCard.append(refs.histPagerTop, histWrap, refs.histPagerBottom,
    refs.histError);

  // Address book.
  refs.bookCard = el('section', 'card card-full');
  refs.bookCard.setAttribute('aria-label', 'Address book');
  refs.bookTitle = el('h2', 'card-title', 'Address book');
  refs.bookCard.appendChild(refs.bookTitle);
  const bookForm = el('form', 'book-form');
  refs.bookAddr = el('input');
  refs.bookAddr.placeholder = 'address';
  refs.bookAddr.spellcheck = false;
  refs.bookAddr.setAttribute('aria-label', 'Address to label');
  refs.bookLabel = el('input');
  refs.bookLabel.placeholder = 'label';
  refs.bookLabel.spellcheck = false;
  refs.bookLabel.setAttribute('aria-label', 'Label');
  const bookBtn = el('button', 'btn', 'set label');
  bookBtn.type = 'submit';
  bookForm.append(refs.bookAddr, refs.bookLabel, bookBtn);
  bookForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const address = refs.bookAddr.value.trim();
    if (!address) return;
    refs.bookError.hidden = true;
    try {
      await rpc.call(...setLabelParams(address, refs.bookLabel.value.trim()),
        endpoint());
      refs.bookAddr.value = '';
      refs.bookLabel.value = '';
      await refreshBook();
    } catch (e) {
      refs.bookError.textContent = rpcErrorMessage(e);
      refs.bookError.hidden = false;
    }
  });
  refs.bookError = el('p', 'error-text');
  refs.bookError.hidden = true;
  const bookWrap = el('div', 'table-wrap');
  const bookTable = el('table', 'peers wtx');
  const bookHead = el('thead');
  const bookHrow = el('tr');
  for (const label of ['address', 'label', 'purpose', 'derivation', '']) {
    bookHrow.appendChild(el('th', '', label));
  }
  bookHead.appendChild(bookHrow);
  refs.bookBody = el('tbody');
  bookTable.append(bookHead, refs.bookBody);
  bookWrap.appendChild(bookTable);
  refs.bookCard.append(bookForm, refs.bookError, bookWrap);

  buildSecurityCard(refs);

  state.refs = refs;
  container.replaceChildren(head, refs.disabledCard, refs.emptyCard,
    refs.balancesCard, refs.infoCard, refs.sendCard, refs.receiveCard,
    refs.historyCard, refs.bookCard, refs.securityCard);
  renderRecipients();
  renderTabStrip();
  applyMask();
  renderVisibility();
}

// --- security: lifecycle + encryption (gui-plan P6d) ---------------------
//
// Qt puts these on menus with a status-bar lock icon (bitcoingui.cpp); a tab
// strip has no menu bar, so they live on their own tab with the lock state as
// a chip. One inline panel is open at a time — see wallet-crypt.js for why
// these are panels rather than modal dialogs.

function passphraseInput(ariaLabel, placeholder = 'passphrase') {
  const input = el('input');
  input.type = 'password';
  input.placeholder = placeholder;
  input.spellcheck = false;
  input.setAttribute('aria-label', ariaLabel);
  return input;
}

// Core's toggleShowPassword (askpassphrasedialog.cpp): one control flips
// every field in the panel, so a user checking a long passphrase does not
// have to reveal them one at a time.
function showPassphraseToggle(inputs) {
  const btn = el('button', 'btn btn-quiet', 'show');
  btn.type = 'button';
  btn.setAttribute('aria-label', 'Show passphrase');
  btn.setAttribute('aria-pressed', 'false');
  btn.addEventListener('click', () => {
    const reveal = btn.getAttribute('aria-pressed') !== 'true';
    for (const i of inputs) i.type = reveal ? 'text' : 'password';
    btn.textContent = reveal ? 'hide' : 'show';
    btn.setAttribute('aria-pressed', String(reveal));
  });
  return btn;
}

function buildSecurityCard(refs) {
  refs.securityCard = el('section', 'card card-full');
  refs.securityCard.setAttribute('aria-label', 'Security');
  refs.securityCard.appendChild(el('h2', 'card-title', 'Security'));

  refs.secStatus = el('div', 'sec-status');
  refs.secActions = el('div', 'sec-actions');
  refs.secPanel = el('div', 'sec-panel');
  refs.secPanel.hidden = true;
  refs.secError = el('p', 'error-text');
  refs.secError.hidden = true;
  refs.secNote = el('p', 'muted');
  refs.secNote.hidden = true;

  refs.securityCard.append(refs.secStatus, refs.secActions, refs.secPanel,
    refs.secError, refs.secNote);
}

function secMessage(text, isError) {
  const { refs } = state;
  refs.secError.hidden = !isError;
  refs.secNote.hidden = isError || !text;
  if (isError) refs.secError.textContent = text;
  else if (text) refs.secNote.textContent = text;
}

// Closing fires the pending on-close callback exactly once — that is how
// promptUnlock learns it was cancelled, rather than polling for it.
function closeSecPanel() {
  const onClose = state.secPanelOnClose;
  state.secPanelOnClose = null;
  state.refs.secPanel.hidden = true;
  state.refs.secPanel.replaceChildren();
  if (onClose) onClose();
}

// Build one inline form. FIELDS are [label, input] rows; SUBMIT runs on
// confirm and returns a status string, or throws to surface an RPC error.
function secForm({ title, warning, fields, submitLabel, onSubmit, danger }) {
  const form = el('form', danger ? 'sec-form danger' : 'sec-form');
  form.setAttribute('aria-label', title);
  form.appendChild(el('h3', 'send-subtitle', title));
  if (warning) form.appendChild(el('p', 'warn-text', warning));
  for (const [label, input] of fields) {
    const row = el('label', 'sec-row');
    row.appendChild(el('span', 'sec-row-label', label));
    row.appendChild(input);
    form.appendChild(row);
  }
  const buttons = el('div', 'send-actions');
  const submit = el('button', danger ? 'btn btn-danger' : 'btn', submitLabel);
  submit.type = 'submit';
  const cancel = el('button', 'btn btn-quiet', 'cancel');
  cancel.type = 'button';
  cancel.addEventListener('click', () => { closeSecPanel(); secMessage('', false); });
  buttons.append(submit, cancel);
  form.appendChild(buttons);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    submit.disabled = true;
    const label = submit.textContent;
    submit.textContent = 'working…';
    secMessage('', false);
    try {
      const note = await onSubmit();
      if (note !== false) {
        closeSecPanel();
        if (note) secMessage(note, false);
      }
    } catch (e) {
      secMessage(rpcErrorMessage(e), true);
    } finally {
      submit.disabled = false;
      submit.textContent = label;
    }
  });
  return form;
}

function openSecPanel(node, onClose = null) {
  const { refs } = state;
  closeSecPanel();               // settles any prompt the previous panel owed
  state.secPanelOnClose = onClose;
  refs.secPanel.replaceChildren(node);
  refs.secPanel.hidden = false;
}

// --- security actions ---------------------------------------------------

function encryptPanel() {
  const pass = passphraseInput('New passphrase');
  const confirm = passphraseInput('Confirm new passphrase');
  return secForm({
    title: 'Encrypt wallet',
    // Core says this twice, before and after; the seed-rotation half is what
    // makes a stale backup dangerous rather than merely out of date.
    warning: `${ENCRYPT_WARNING} ${ENCRYPT_BACKUP_WARNING} ${PASSPHRASE_HINT}`,
    danger: true,
    fields: [
      ['Passphrase', pass],
      ['Confirm', confirm],
      ['', showPassphraseToggle([pass, confirm])],
    ],
    submitLabel: 'encrypt wallet',
    onSubmit: async () => {
      const bad = validatePassphrasePair(pass.value, confirm.value);
      if (bad) { secMessage(bad, true); return false; }
      const note = await rpc.call('encryptwallet', [pass.value], endpoint());
      forgetPassphrase(pass, confirm);
      // The seed rotated: every address the page is holding is from the old
      // one. Reload rather than patching state.
      await refresh();
      return typeof note === 'string' ? note : 'Wallet encrypted.';
    },
  });
}

function unlockPanel(onDone) {
  const pass = passphraseInput('Passphrase');
  const timeout = el('select');
  timeout.setAttribute('aria-label', 'Unlock for');
  for (const [secs, label] of UNLOCK_TIMEOUTS) {
    const opt = el('option', '', label);
    opt.value = String(secs);
    timeout.appendChild(opt);
  }
  timeout.value = String(DEFAULT_UNLOCK_TIMEOUT);
  return secForm({
    title: 'Unlock wallet',
    warning: 'The wallet relocks automatically when the time is up.',
    fields: [
      ['Passphrase', pass],
      ['Unlock for', timeout],
      ['', showPassphraseToggle([pass])],
    ],
    submitLabel: 'unlock',
    onSubmit: async () => {
      if (!pass.value) { secMessage('Enter a passphrase.', true); return false; }
      const badTimeout = validateTimeout(timeout.value);
      if (badTimeout) { secMessage(badTimeout, true); return false; }
      await rpc.call('walletpassphrase',
        unlockParams(pass.value, timeout.value), endpoint());
      forgetPassphrase(pass);
      await refreshWalletInfo();
      renderSecurity();
      if (onDone) onDone(true);
      return 'Wallet unlocked.';
    },
  });
}

function changePanel() {
  const oldPass = passphraseInput('Current passphrase');
  const pass = passphraseInput('New passphrase');
  const confirm = passphraseInput('Confirm new passphrase');
  return secForm({
    title: 'Change passphrase',
    warning: PASSPHRASE_HINT,
    fields: [
      ['Current', oldPass],
      ['New', pass],
      ['Confirm', confirm],
      ['', showPassphraseToggle([oldPass, pass, confirm])],
    ],
    submitLabel: 'change passphrase',
    onSubmit: async () => {
      const bad = validatePassphrasePair(pass.value, confirm.value);
      if (bad) { secMessage(bad, true); return false; }
      await rpc.call('walletpassphrasechange', [oldPass.value, pass.value], endpoint());
      forgetPassphrase(oldPass, pass, confirm);
      await refreshWalletInfo();
      renderSecurity();
      return 'Passphrase changed.';
    },
  });
}

function backupPanel() {
  const dest = el('input');
  dest.placeholder = '/path/on/the/node/wallet-backup.dump';
  dest.spellcheck = false;
  dest.setAttribute('aria-label', 'Backup destination path');
  return secForm({
    title: 'Back up wallet',
    // The path is resolved by the NODE, not the browser — easy to get wrong
    // when the UI is reached through a tunnel.
    warning: 'The path is on the machine running the node, not this computer. '
      + 'An encrypted wallet backs up while locked; the backup holds only '
      + 'ciphertext.',
    fields: [['Destination', dest]],
    submitLabel: 'back up',
    onSubmit: async () => {
      if (!dest.value) { secMessage('Enter a destination path.', true); return false; }
      await rpc.call('backupwallet', [dest.value], endpoint());
      return `Wallet backed up to ${dest.value}.`;
    },
  });
}

function restorePanel() {
  const name = el('input');
  name.placeholder = 'new wallet name';
  name.spellcheck = false;
  name.setAttribute('aria-label', 'Restored wallet name');
  const file = el('input');
  file.placeholder = '/path/on/the/node/wallet-backup.dump';
  file.spellcheck = false;
  file.setAttribute('aria-label', 'Backup file path');
  return secForm({
    title: 'Restore wallet from backup',
    warning: 'The backup file is read on the machine running the node. '
      + 'Restoring never overwrites an existing wallet.',
    fields: [['Wallet name', name], ['Backup file', file]],
    submitLabel: 'restore',
    onSubmit: async () => {
      if (!name.value || !file.value) {
        secMessage('Enter a wallet name and a backup file path.', true);
        return false;
      }
      const res = await rpc.call('restorewallet', [name.value, file.value]);
      const warnings = (res && res.warnings) || [];
      await selectWallet(name.value);
      return warnings.length
        ? `Restored ${name.value}. ${warnings.join(' ')}`
        : `Restored ${name.value}.`;
    },
  });
}

function createPanel() {
  const name = el('input');
  name.placeholder = 'wallet name';
  name.spellcheck = false;
  name.setAttribute('aria-label', 'New wallet name');
  const pass = passphraseInput('New wallet passphrase (optional)',
    'passphrase (optional)');
  const confirm = passphraseInput('Confirm new wallet passphrase',
    'confirm passphrase');
  const watchOnly = el('input');
  watchOnly.type = 'checkbox';
  watchOnly.setAttribute('aria-label', 'Watch-only (disable private keys)');
  const blank = el('input');
  blank.type = 'checkbox';
  blank.setAttribute('aria-label', 'Blank (no keys or descriptors)');
  return secForm({
    title: 'Create wallet',
    warning: 'A passphrase encrypts the new wallet from the start, so no '
      + 'unencrypted key material is ever written to disk. ' + PASSPHRASE_HINT,
    fields: [
      ['Name', name],
      ['Passphrase', pass],
      ['Confirm', confirm],
      ['', showPassphraseToggle([pass, confirm])],
      ['Watch-only', watchOnly],
      ['Blank', blank],
    ],
    submitLabel: 'create wallet',
    onSubmit: async () => {
      // One model for both the check and the call, so they cannot drift.
      const form = {
        name: name.value,
        disablePrivateKeys: watchOnly.checked,
        blank: blank.checked,
        passphrase: pass.value,
        confirm: confirm.value,
      };
      const bad = validateCreate(form);
      if (bad) { secMessage(bad, true); return false; }
      const res = await rpc.call('createwallet', createParams(form));
      forgetPassphrase(pass, confirm);
      const warnings = (res && res.warnings) || [];
      await selectWallet(name.value);
      return warnings.length
        ? `Created ${name.value}. ${warnings.join(' ')}`
        : `Created ${name.value}.`;
    },
  });
}

async function lockNow() {
  try {
    await rpc.call('walletlock', [], endpoint());
    await refreshWalletInfo();
    renderSecurity();
    secMessage('Wallet locked.', false);
  } catch (e) {
    secMessage(rpcErrorMessage(e), true);
  }
}

async function unloadCurrent() {
  const name = state.selected;
  try {
    await rpc.call('unloadwallet', [name]);
    sessionStorage.removeItem(WALLET_KEY);
    state.selected = null;
    closeSecPanel();
    await refresh();
    secMessage(`Unloaded ${name}.`, false);
  } catch (e) {
    secMessage(rpcErrorMessage(e), true);
  }
}

function secButton(label, onClick) {
  const btn = el('button', 'btn', label);
  btn.type = 'button';
  btn.addEventListener('click', onClick);
  return btn;
}

function renderSecurity() {
  const { refs } = state;
  if (!haveWallet()) return;
  const info = state.walletinfo;
  const st = encryptionState(info);

  const { label: stLabel, variant } = STATE_UI[st];
  const chip = pill(stLabel, variant);
  chip.setAttribute('aria-label', `Encryption state: ${stLabel}`);
  const bits = [chip];
  if (st === 'unlocked') {
    const left = unlockCountdown(info);
    if (left) bits.push(el('span', 'muted mono sec-countdown', `relocks in ${left}`));
  }
  if (st === 'no-keys') {
    bits.push(el('span', 'muted',
      'watch-only wallets hold no private keys, so there is nothing to encrypt'));
  }
  refs.secStatus.replaceChildren(...bits);

  // Rebuild the action row only when the state it acts on changed, so an
  // armed confirm is never reset by the background poll — the same guard
  // peers.js uses on its network toggle. Without it the 3s refresh replaces
  // the armed "unload" button before its 4s window elapses, so the confirm
  // click lands on a fresh, disarmed button and silently does nothing.
  const stamp = `${st}|${state.selected}`;
  if (refs.secActionsFor === stamp) return;
  refs.secActionsFor = stamp;

  const actions = [];
  if (st === 'unencrypted') {
    actions.push(secButton('encrypt wallet…',
      () => openSecPanel(encryptPanel())));
  }
  if (st === 'locked') {
    actions.push(secButton('unlock…', () => openSecPanel(unlockPanel())));
  }
  if (st === 'unlocked') {
    actions.push(secButton('lock now', lockNow));
  }
  if (isEncrypted(st)) {
    actions.push(secButton('change passphrase…',
      () => openSecPanel(changePanel())));
  }
  actions.push(secButton('back up…', () => openSecPanel(backupPanel())));
  actions.push(secButton('restore…', () => openSecPanel(restorePanel())));
  actions.push(secButton('create wallet…', () => openSecPanel(createPanel())));
  actions.push(armedButton(`unload ${state.selected}`, 'confirm unload',
    unloadCurrent, 'btn btn-quiet'));
  refs.secActions.replaceChildren(...actions);
}

// Core's WalletModel::requestUnlock, wired to the Security tab's unlock
// panel: raise it, and resolve once the wallet is no longer locked.
function promptUnlock() {
  return new Promise((resolve) => {
    // Qt raises a modal over whatever view you were on and returns you to it.
    // We move to the Security tab (that is where the panel lives), so we owe
    // the caller the trip back — otherwise a send leaves the user stranded
    // here with a compose form they cannot see.
    const cameFrom = state.tab;
    let unlocked = false;
    show(state.container, 'security');
    // Resolve from the panel CLOSING, which is the event that actually
    // happens — on submit, on cancel, and if anything else replaces the
    // panel. closeSecPanel clears the callback before firing it, so this
    // settles exactly once and needs no guard.
    openSecPanel(unlockPanel(() => { unlocked = true; }), () => {
      if (cameFrom !== 'security') show(state.container, cameFrom);
      resolve(unlocked);
    });
    secMessage('This wallet is locked — unlock it to sign.', false);
  });
}

const unlockDeps = {
  // Re-read rather than trusting whatever the page is holding: only the
  // Overview and Security tabs refresh getwalletinfo, so a spend composed on
  // the Send tab would otherwise decide the lock state from a stale — or
  // entirely absent — object and skip the gate.
  state: async () => { await refreshWalletInfo(); return state.walletinfo; },
  prompt: promptUnlock,
  lock: async () => {
    try { await rpc.call('walletlock', [], endpoint()); } catch { /* best effort */ }
    await refreshWalletInfo();
    renderSecurity();
  },
};

// THE seam for anything that needs the wallet's private keys. Exported
// because it is not send-specific: every node RPC behind
// wallet-ensure-unlocked (src/rpc/wallet.lisp) belongs behind this —
// signrawtransactionwithwallet, walletprocesspsbt, bumpfee, signmessage,
// importdescriptors, keypoolrefill, listdescriptors(true). gui-plan 6c adds
// the PSBT panel and bumpfee; they call this rather than re-deriving a
// prompt, so a locked wallet can never reach them as a raw -13.
// Throws UnlockCancelled when the user dismisses the prompt.
export function withWalletUnlocked(fn) {
  return withUnlocked(unlockDeps, fn);
}

// --- visibility & chrome -------------------------------------------------

function haveWallet() {
  return !state.disabled && state.selected !== null;
}

function renderVisibility() {
  const { refs } = state;
  refs.disabledCard.hidden = !state.disabled;
  refs.emptyCard.hidden = state.disabled || state.wallets.length > 0;
  refs.select.hidden = state.disabled || state.wallets.length === 0;
  refs.watchPill.hidden = !haveWallet()
    || state.walletinfo?.private_keys_enabled !== false;
  refs.maskBtn.hidden = state.disabled;
  refs.tabstrip.hidden = !haveWallet();
  const show = (node, tab) => {
    node.hidden = !haveWallet() || state.tab !== tab;
  };
  show(refs.balancesCard, 'overview');
  show(refs.infoCard, 'overview');
  show(refs.sendCard, 'send');
  show(refs.receiveCard, 'receive');
  show(refs.historyCard, 'history');
  show(refs.bookCard, 'addresses');
  show(refs.securityCard, 'security');
}

function renderTabStrip() {
  const { refs } = state;
  for (const a of refs.tabstrip.children) {
    const active = a.dataset.tab === state.tab;
    a.classList.toggle('active', active);
    if (active) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
}

function applyMask() {
  const masked = isMasked();
  state.container.classList.toggle('mask-on', masked);
  state.refs.maskBtn.textContent = masked ? 'show amounts' : 'hide amounts';
  state.refs.maskBtn.setAttribute('aria-pressed', String(masked));
}

function selectWallet(name) {
  if (name) sessionStorage.setItem(WALLET_KEY, name);
  state.selected = name || null;
  state.balances = null;
  state.walletinfo = null;
  state.histPage = 0;
  state.histEntries = [];
  state.histHasMore = false;
  state.expandedKey = null;
  state.txDetails = new Map();
  state.bookRows = [];
  state.receive = null;
  state.send = freshSend();
  if (state.refs) {
    state.refs.histStamp = null;
    state.refs.receiveResult.replaceChildren();
    state.refs.receiveError.hidden = true;
    state.refs.sendError.hidden = true;
    renderRecipients();
    renderReview();
    renderSendResult();
  }
  return refresh();
}

// --- refresh: wallet list first, then the visible tab's data -------------

// Re-fetch and re-render. No-ops while the wallet view is off screen so
// app.js can call it from the shared 3s poll unconditionally.
export async function refresh() {
  const { container, refs } = state;
  if (!container || container.hidden || !refs || state.refreshing) return;
  state.refreshing = true;
  try {
    await refreshWalletList();
    renderVisibility();
    if (haveWallet()) {
      if (state.tab === 'overview') await refreshOverview();
      else if (state.tab === 'history') await refreshHistory();
      else if (state.tab === 'addresses') {
        if (state.bookRows.length === 0) await refreshBook();
        // Otherwise the book only refreshes on demand — a 3s rebuild would
        // clobber an inline label edit in progress.
      } else if (state.tab === 'security') {
        // getwalletinfo carries both fields the encryption state is derived
        // from; re-read it every poll so the countdown ticks and a relock
        // (sweeper or timeout) shows up without a manual reload.
        await refreshWalletInfo();
        renderSecurity();
      }
      renderVisibility(); // watch-only pill state may have just arrived
    }
  } finally {
    state.refreshing = false;
  }
}

async function refreshWalletList() {
  const { refs } = state;
  let wallets;
  try {
    wallets = await rpc.call('listwallets');
    state.disabled = false;
  } catch (e) {
    if (e instanceof rpc.RpcError && e.code === -32601) {
      // No-wallet build / -nowallet: a clear state, not a broken page.
      state.disabled = true;
      state.wallets = [];
      state.selected = null;
      refs.loadRow.hidden = true;
      refs.loadStamp = null;
      return;
    }
    throw e;
  }
  state.wallets = wallets || [];

  // Keep (or re-establish) the selection: the stored name if loaded, else
  // the first loaded wallet.
  const stored = sessionStorage.getItem(WALLET_KEY);
  let selected = state.selected ?? stored;
  if (!state.wallets.includes(selected)) selected = state.wallets[0] ?? null;
  if (selected !== state.selected) {
    state.selected = selected;
    state.balances = null;
    state.walletinfo = null;
  }

  // Selector options (rebuilt only on change, so an open dropdown is never
  // clobbered by the poll).
  const stamp = JSON.stringify([state.wallets, state.selected]);
  if (refs.selectStamp !== stamp) {
    refs.selectStamp = stamp;
    refs.select.replaceChildren(...state.wallets.map((name) => {
      const opt = el('option', '', name);
      opt.value = name;
      return opt;
    }));
    refs.select.value = state.selected ?? '';
  }

  // Load picker from listwalletdir (shown when unloaded wallets exist).
  let dir = null;
  try {
    dir = await rpc.call('listwalletdir');
  } catch { /* keep the last picker state */ }
  if (dir) {
    const unloaded = unloadedWallets(dir, state.wallets);
    const dirStamp = JSON.stringify(unloaded);
    if (refs.loadStamp !== dirStamp) {
      refs.loadStamp = dirStamp;
      refs.loadRow.hidden = unloaded.length === 0;
      refs.loadSelect.replaceChildren(...unloaded.map((name) => {
        const opt = el('option', '', name);
        opt.value = name;
        return opt;
      }));
    }
  }
}

// --- overview -------------------------------------------------------------

// Just getwalletinfo — what the Security tab's state derivation needs. A
// failure here leaves the previous object in place rather than blanking the
// tab: encryptionState(undefined) is 'unknown', which would hide every
// control including the unlock button.
async function refreshWalletInfo() {
  const { refs } = state;
  try {
    state.walletinfo = await rpc.call('getwalletinfo', [], endpoint());
    refs.secError.hidden = true;
  } catch (e) {
    secMessage(rpcErrorMessage(e), true);
  }
}

async function refreshOverview() {
  const { refs } = state;
  const [balR, infoR, heightR] = await rpc.batch(
    [['getbalances'], ['getwalletinfo'], ['getblockcount']], endpoint());
  const failed = balR.error || infoR.error;
  refs.overviewError.hidden = !failed;
  if (failed) refs.overviewError.textContent = (balR.error || infoR.error).message;
  if (!balR.error) state.balances = balR.result;
  if (!infoR.error) state.walletinfo = infoR.result;
  if (!heightR.error) state.chainHeight = heightR.result;
  renderOverview();
}

function renderOverview() {
  const { refs, balances, walletinfo } = state;
  if (balances) {
    const mine = balances.mine || {};
    const total = (mine.trusted ?? 0) + (mine.untrusted_pending ?? 0)
      + (mine.immature ?? 0);
    refs.balTotal.replaceChildren(amt(fmtBtc(total)));
    const kv = [];
    kv.push(kvRow('available (trusted)', amt(fmtBtc(mine.trusted))));
    kv.push(kvRow('pending (untrusted)', amt(fmtBtc(mine.untrusted_pending))));
    kv.push(kvRow('immature (mined)', amt(fmtBtc(mine.immature))));
    if (mine.used !== undefined) {
      kv.push(kvRow('used (avoid-reuse)', amt(fmtBtc(mine.used))));
    }
    const lpb = balances.lastprocessedblock;
    if (lpb) {
      const behind = state.chainHeight !== null
        ? state.chainHeight - (lpb.height ?? 0) : null;
      const fresh = behind !== null && behind <= 0;
      kv.push(kvRow('last processed block',
        link(`#/block/${lpb.hash}`, `#${fmtInt(lpb.height)}`),
        el('span', fresh ? 'wallet-fresh' : 'wallet-stale',
          behind === null ? '' : (fresh ? ' · at node tip'
            : ` · ${fmtInt(behind)} block${behind === 1 ? '' : 's'} behind`))));
    }
    refs.balKv.replaceChildren(...kv);
  }
  if (walletinfo) {
    const rows = [];
    rows.push(kvRow('wallet', walletinfo.walletname || '(default)'));
    rows.push(kvRow('transactions', fmtInt(walletinfo.txcount)));
    rows.push(kvRow('keypool (external · internal)',
      `${fmtInt(walletinfo.keypoolsize)} · ${fmtInt(walletinfo.keypoolsize_hd_internal)}`));
    rows.push(kvRow('private keys',
      walletinfo.private_keys_enabled ? 'enabled' : 'disabled (watch-only)'));
    rows.push(kvRow('avoid reuse', walletinfo.avoid_reuse ? 'yes' : 'no'));
    rows.push(kvRow('format',
      `${walletinfo.format ?? '—'}${walletinfo.descriptors ? ' · descriptors' : ''}`));
    if (walletinfo.birthtime) {
      rows.push(kvRow('birth time',
        `${fmtTimestamp(walletinfo.birthtime)} (${fmtAge(walletinfo.birthtime)} ago)`));
    }
    const scanning = walletinfo.scanning;
    if (scanning && typeof scanning === 'object') {
      rows.push(kvRow('scanning',
        `${fmtPct(scanning.progress)} · running ${fmtDuration(scanning.duration)}`));
    } else {
      rows.push(kvRow('scanning', 'no'));
    }
    refs.infoKv.replaceChildren(...rows);
  }
}

// --- receive ------------------------------------------------------------

async function generateAddress() {
  const { refs } = state;
  refs.receiveError.hidden = true;
  refs.recvBtn.disabled = true;
  const label = refs.recvLabel.value.trim();
  const type = refs.recvType.value;
  try {
    const address = await rpc.call(...newAddressParams(label, type), endpoint());
    state.receive = { address, label, type, uri: bip21Uri(address, label) };
    renderReceive();
    // Derivation detail is best-effort decoration; the address stands alone.
    try {
      state.receive.info = await rpc.call('getaddressinfo', [address], endpoint());
      renderReceive();
    } catch { /* leave the card without derivation info */ }
  } catch (e) {
    refs.receiveError.textContent = rpcErrorMessage(e);
    refs.receiveError.hidden = false;
  } finally {
    refs.recvBtn.disabled = false;
  }
}

function renderReceive() {
  const { refs, receive } = state;
  if (!receive) return;
  const box = el('div', 'receive-box');

  const img = el('img', 'qr-img');
  img.src = qrDataUri(receive.uri);
  img.alt = `QR code for ${receive.uri}`;
  img.width = 220;
  img.height = 220;
  box.appendChild(img);

  const kv = el('dl', 'kv receive-kv');
  kv.appendChild(kvRow('address', copyable(receive.address)));
  kv.appendChild(kvRow('payment URI', copyable(receive.uri, shortId(receive.uri, 24))));
  if (receive.label) kv.appendChild(kvRow('label', receive.label));
  kv.appendChild(kvRow('type', receive.type));
  const info = receive.info;
  if (info) {
    if (info.hdkeypath) kv.appendChild(kvRow('derivation path', info.hdkeypath));
    if (info.parent_desc) {
      kv.appendChild(kvRow('parent descriptor',
        copyable(info.parent_desc, shortId(info.parent_desc, 18))));
    }
    if (info.ismine === false) {
      kv.appendChild(kvRow('warning', el('span', 'error-text',
        'the wallet does not recognize this address as its own')));
    }
  }
  box.appendChild(kv);
  refs.receiveResult.replaceChildren(box);
}

// --- send -----------------------------------------------------------------

// Rebuild the recipient rows from the model, preserving element handles for
// syncing values back out of the DOM.
function renderRecipients() {
  const { refs, send } = state;
  if (!refs) return;
  const rowRefs = [];
  const nodes = send.recipients.map((model, i) => {
    const row = el('div', 'send-row');
    const addr = el('input', 'send-addr');
    addr.setAttribute('aria-label', `Recipient ${i + 1} address`);
    addr.placeholder = 'address';
    addr.spellcheck = false;
    addr.value = model.address;
    const amount = el('input', 'send-amt');
    amount.setAttribute('aria-label', `Recipient ${i + 1} amount (BTC)`);
    amount.placeholder = 'amount (BTC)';
    amount.spellcheck = false;
    amount.value = model.amount;
    row.append(addr, amount);
    if (send.recipients.length > 1) {
      const rm = el('button', 'btn send-rm', 'remove');
      rm.type = 'button';
      rm.setAttribute('aria-label', `Remove recipient ${i + 1}`);
      rm.addEventListener('click', () => removeRecipient(i));
      row.append(rm);
    }
    rowRefs.push({ addr, amount });
    return row;
  });
  send.rowRefs = rowRefs;
  refs.sendRecipients.replaceChildren(...nodes);
}

// Pull the live input/control values into the model (so add/remove never
// drops half-typed rows, and review reads the latest text).
function syncSendFromDom() {
  const { refs, send } = state;
  send.rowRefs.forEach((ref, i) => {
    if (send.recipients[i]) {
      send.recipients[i].address = ref.addr.value;
      send.recipients[i].amount = ref.amount.value;
    }
  });
  send.confTarget = Number(refs.sendConfTarget.value) || DEFAULT_CONF_TARGET;
  send.rbf = !!refs.sendRbf.checked;
  send.sffo = !!refs.sendSffo.checked;
}

function addRecipient() {
  syncSendFromDom();
  state.send.recipients.push({ address: '', amount: '' });
  renderRecipients();
}

function removeRecipient(index) {
  syncSendFromDom();
  state.send.recipients.splice(index, 1);
  if (state.send.recipients.length === 0) {
    state.send.recipients.push({ address: '', amount: '' });
  }
  renderRecipients();
}

function fmtRecipientError(e) {
  return e.index >= 0 ? `recipient ${e.index + 1} ${e.field}: ${e.reason}` : e.reason;
}

// Review: validate every row, then price the spend via estimatesmartfee (a
// node method on the base endpoint) and show the confirm panel.
async function onReviewSend() {
  const { refs, send } = state;
  syncSendFromDom();
  refs.sendError.hidden = true;
  send.result = null;
  renderSendResult();

  const check = validateRecipients(send.recipients);
  if (!check.ok) {
    refs.sendError.textContent = check.errors.map(fmtRecipientError).join('; ');
    refs.sendError.hidden = false;
    send.reviewing = false;
    send.preview = null;
    renderReview();
    return;
  }
  send.cleaned = check.cleaned;

  let feerate = null;
  let blocks = send.confTarget;
  let errors = null;
  try {
    const est = await rpc.call(...estimateFeeParams(send.confTarget, send.rbf));
    feerate = est?.feerate ?? null;
    blocks = est?.blocks ?? send.confTarget;
    errors = est?.errors ?? null;
  } catch (e) {
    errors = [rpcErrorMessage(e)];
  }
  const vsize = estimateVsize(send.cleaned.length);
  const satPerVb = feerate != null ? (feerate * 1e8) / 1000 : null;
  const feeSats = satPerVb != null ? Math.round(satPerVb * vsize) : null;
  send.preview = {
    feerate, blocks, errors, vsize, feeSats, rbf: send.rbf, sffo: send.sffo,
  };
  send.reviewing = true;
  renderReview();
}

function renderReview() {
  const { refs, send } = state;
  if (!refs) return;
  if (!send.reviewing || !send.preview) {
    refs.sendReview.hidden = true;
    refs.sendReview.replaceChildren();
    return;
  }
  const p = send.preview;
  const box = el('div', 'send-review');
  box.appendChild(el('h3', 'send-subtitle', 'Review send'));

  const kv = el('dl', 'kv');
  let total = 0n;
  send.cleaned.forEach((r, i) => {
    total += r.sats;
    kv.appendChild(kvRow(`to ${i + 1}`,
      el('span', 'mono', shortId(r.address, 14)),
      el('span', 'sep', '·'),
      el('span', 'mono', `${r.amount} BTC`)));
  });
  kv.appendChild(kvRow('total to send', el('span', 'mono', fmtSatsBtc(total))));
  kv.appendChild(kvRow('confirmation target',
    `${fmtInt(p.blocks)} block${p.blocks === 1 ? '' : 's'}`));
  kv.appendChild(kvRow('fee rate',
    p.feerate != null ? fmtFeeRate(p.feerate) : 'node fallback (no estimate)'));
  kv.appendChild(kvRow('estimated fee',
    el('span', 'mono', p.feeSats != null ? `≈ ${fmtSatsBtc(BigInt(p.feeSats))}` : '—'),
    el('span', 'muted', ` · ~${fmtInt(p.vsize)} vB, exact fee set when built`)));
  kv.appendChild(kvRow('replace-by-fee', p.rbf ? 'signaled (BIP125)' : 'not signaled'));
  kv.appendChild(kvRow('subtract fee from outputs', p.sffo ? 'yes' : 'no'));
  box.appendChild(kv);
  if (p.errors && p.errors.length) {
    box.appendChild(el('p', 'muted', `fee estimate: ${p.errors.join('; ')}`));
  }

  const actions = el('div', 'send-actions');
  const confirm = el('button', 'btn send-confirm', 'confirm and send');
  confirm.type = 'button';
  confirm.addEventListener('click', () => onConfirmSend(confirm));
  const edit = el('button', 'linklike', 'edit');
  edit.type = 'button';
  edit.addEventListener('click', () => {
    send.reviewing = false;
    renderReview();
  });
  actions.append(confirm, edit);
  box.appendChild(actions);

  refs.sendReview.hidden = false;
  refs.sendReview.replaceChildren(box);
}

async function onConfirmSend(btn) {
  const { refs, send } = state;
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'sending…';
  refs.sendError.hidden = true;
  try {
    const [method, params] = buildSendCall({
      recipients: send.cleaned,
      confTarget: send.confTarget,
      rbf: send.rbf,
      subtractFee: send.sffo,
    });
    // Core's UnlockContext (walletmodel.cpp:428): prompt BEFORE signing when
    // the wallet is locked, and relock afterwards if it was locked to begin
    // with — rather than letting the node answer -13 and leaving the wallet
    // open once the user retries. Cancelling leaves the compose form intact.
    const result = await withWalletUnlocked(
      () => rpc.call(method, params, endpoint()));
    send.result = {
      txid: sendResultTxid(result),
      feeReason: (result && result.fee_reason) || null,
    };
    // Reset the compose form to a single blank recipient after a broadcast.
    send.recipients = [{ address: '', amount: '' }];
    send.cleaned = [];
    send.reviewing = false;
    send.preview = null;
    renderRecipients();
    renderReview();
    renderSendResult();
  } catch (e) {
    send.result = { error: rpcErrorMessage(e) };
    renderSendResult();
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
}

function renderSendResult() {
  const { refs, send } = state;
  if (!refs) return;
  if (!send.result) {
    refs.sendResult.hidden = true;
    refs.sendResult.replaceChildren();
    return;
  }
  refs.sendResult.hidden = false;
  if (send.result.error) {
    refs.sendResult.replaceChildren(el('p', 'error-text', send.result.error));
    return;
  }
  const box = el('div', 'send-result');
  box.appendChild(el('p', 'send-ok', 'Transaction broadcast.'));
  const kv = el('dl', 'kv');
  kv.appendChild(kvRow('txid',
    copyable(send.result.txid, shortId(send.result.txid, 16)),
    el('span', 'sep', '·'),
    link(`#/tx/${send.result.txid}`, 'open in explorer')));
  if (send.result.feeReason) {
    kv.appendChild(kvRow('fee reason', send.result.feeReason));
  }
  box.appendChild(kv);
  refs.sendResult.replaceChildren(box);
}

// --- history --------------------------------------------------------------

async function refreshHistory() {
  const { refs } = state;
  let result;
  try {
    result = await rpc.call(...historyParams(state.histPage), endpoint());
  } catch (e) {
    refs.histError.textContent = rpcErrorMessage(e);
    refs.histError.hidden = false;
    return;
  }
  refs.histError.hidden = true;
  const { entries, hasMore } = historyPage(result);
  state.histEntries = entries;
  state.histHasMore = hasMore;
  renderHistory();
}

function gotoHistoryPage(page) {
  state.histPage = Math.max(0, page);
  state.expandedKey = null;
  return refreshHistory();
}

function renderHistoryPager(node) {
  const { histPage, histHasMore, histEntries } = state;
  node.replaceChildren();
  if (histPage === 0 && !histHasMore) return;
  const prev = el('button', 'btn', '‹ newer');
  prev.type = 'button';
  prev.disabled = histPage <= 0;
  prev.addEventListener('click', () => gotoHistoryPage(histPage - 1));
  const next = el('button', 'btn', 'older ›');
  next.type = 'button';
  next.disabled = !histHasMore;
  next.addEventListener('click', () => gotoHistoryPage(histPage + 1));
  const fromN = histPage * HISTORY_PAGE_SIZE + 1;
  node.append(prev,
    el('span', 'pager-label',
      histEntries.length === 0 ? '—'
        : `entries ${fmtInt(fromN)}–${fmtInt(fromN + histEntries.length - 1)}, newest first`),
    next);
}

function renderHistory() {
  const { refs } = state;
  // Skip DOM rebuilds when nothing changed so the poll never closes an
  // expanded detail row or swaps a row (or pager button) mid-click. The
  // expanded entry's fetched detail is part of the identity — its arrival
  // must re-render.
  const expandedEntry = state.histEntries.find(
    (e) => entryKey(e) === state.expandedKey);
  const stamp = JSON.stringify([state.histEntries, state.expandedKey,
    state.histPage, state.histHasMore,
    expandedEntry ? state.txDetails.get(expandedEntry.txid) ?? null : null]);
  if (refs.histStamp === stamp) return;
  refs.histStamp = stamp;

  refs.histTitle.textContent = `History${state.histPage > 0 ? ` (page ${state.histPage + 1})` : ''}`;
  renderHistoryPager(refs.histPagerTop);
  renderHistoryPager(refs.histPagerBottom);

  if (state.histEntries.length === 0) {
    const tr = el('tr');
    const td = el('td', 'muted', state.histPage === 0
      ? 'no wallet transactions yet' : 'no entries on this page');
    td.colSpan = 6;
    tr.appendChild(td);
    refs.histBody.replaceChildren(tr);
    return;
  }

  const rows = [];
  for (const entry of state.histEntries) {
    const key = entryKey(entry);
    const tr = el('tr', key === state.expandedKey ? 'selected' : '');
    tr.tabIndex = 0;
    tr.setAttribute('role', 'button');
    tr.setAttribute('aria-label', `Transaction ${entry.txid} details`);
    const toggle = () => toggleExpand(key, entry.txid);
    tr.addEventListener('click', toggle);
    tr.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(); }
    });

    const catTd = el('td');
    catTd.appendChild(pill(entry.category, categoryVariant(entry.category)));
    if (entry.abandoned) catTd.appendChild(pill('abandoned', 'pill-bad'));
    tr.appendChild(catTd);
    const amtTd = el('td', 'num');
    amtTd.appendChild(amt(fmtBtc(entry.amount)));
    tr.appendChild(amtTd);
    tr.appendChild(el('td', 'num', fmtInt(entry.confirmations)));
    tr.appendChild(el('td', '', entry.label ?? ''));
    tr.appendChild(el('td', 'mono', entry.address ? shortId(entry.address, 12) : '—'));
    tr.appendChild(el('td', '', entry.time ? `${fmtAge(entry.time)} ago` : '—'));
    rows.push(tr);

    if (key === state.expandedKey) {
      const dtr = el('tr', 'tx-detail-row');
      const td = el('td');
      td.colSpan = 6;
      td.appendChild(detailNode(entry));
      dtr.appendChild(td);
      rows.push(dtr);
    }
  }
  refs.histBody.replaceChildren(...rows);
}

async function toggleExpand(key, txid) {
  if (state.expandedKey === key) {
    state.expandedKey = null;
    renderHistory();
    return;
  }
  state.expandedKey = key;
  renderHistory(); // opens immediately with a loading state
  if (!state.txDetails.has(txid)) {
    try {
      const detail = await rpc.call('gettransaction', [txid], endpoint());
      state.txDetails.set(txid, detail);
    } catch (e) {
      state.txDetails.set(txid, { __error: rpcErrorMessage(e) });
    }
    if (state.expandedKey === key) renderHistory();
  }
}

// The expanded gettransaction panel for a history entry.
function detailNode(entry) {
  const detail = state.txDetails.get(entry.txid);
  const box = el('div', 'tx-detail');
  if (!detail) {
    box.appendChild(el('p', 'muted', 'loading transaction detail…'));
    return box;
  }
  if (detail.__error) {
    box.appendChild(el('p', 'error-text', detail.__error));
    return box;
  }
  const kv = el('dl', 'kv');
  kv.appendChild(kvRow('txid', copyable(detail.txid, shortId(detail.txid, 16)),
    el('span', 'sep', '·'), link(`#/tx/${detail.txid}`, 'open in explorer')));
  if (detail.wtxid && detail.wtxid !== detail.txid) {
    kv.appendChild(kvRow('wtxid', copyable(detail.wtxid, shortId(detail.wtxid, 16))));
  }
  kv.appendChild(kvRow('net amount', amt(fmtBtc(detail.amount))));
  if (detail.fee !== undefined) {
    kv.appendChild(kvRow('fee', amt(fmtBtc(detail.fee))));
  }
  kv.appendChild(kvRow('confirmations', fmtInt(detail.confirmations)));
  if (detail.generated) kv.appendChild(kvRow('generated', 'yes (coinbase)'));
  if (detail.trusted !== undefined) {
    kv.appendChild(kvRow('trusted', detail.trusted ? 'yes' : 'no'));
  }
  if (detail.blockhash) {
    kv.appendChild(kvRow('block',
      link(`#/block/${detail.blockhash}`, shortHash(detail.blockhash)),
      el('span', 'muted', detail.blockheight !== undefined
        ? ` · height ${fmtInt(detail.blockheight)}` : '')));
  }
  kv.appendChild(kvRow('replaceable (BIP125)', detail['bip125-replaceable'] ?? 'no'));
  const conflicts = detail.walletconflicts || [];
  kv.appendChild(kvRow('wallet conflicts', conflicts.length === 0 ? 'none'
    : ''));
  for (const c of conflicts) {
    kv.appendChild(kvRow('· conflict', link(`#/tx/${c}`, shortId(c, 16))));
  }
  const mconflicts = detail.mempoolconflicts || [];
  if (mconflicts.length > 0) {
    for (const c of mconflicts) {
      kv.appendChild(kvRow('· mempool conflict', link(`#/tx/${c}`, shortId(c, 16))));
    }
  }
  if (detail.time) kv.appendChild(kvRow('time', fmtTimestamp(detail.time)));
  if (detail.timereceived) {
    kv.appendChild(kvRow('received', fmtTimestamp(detail.timereceived)));
  }
  box.appendChild(kv);
  return box;
}

// --- address book ----------------------------------------------------

const BOOK_INFO_LIMIT = 60; // getaddressinfo decoration cap per refresh

async function refreshBook() {
  const { refs } = state;
  let labels;
  try {
    labels = await rpc.call('listlabels', [], endpoint());
  } catch (e) {
    refs.bookError.textContent = rpcErrorMessage(e);
    refs.bookError.hidden = false;
    return;
  }
  refs.bookError.hidden = true;

  let rows = [];
  if ((labels || []).length > 0) {
    const results = await rpc.batch(
      labels.map((label) => ['getaddressesbylabel', [label]]), endpoint());
    labels.forEach((label, i) => {
      // -11: the label vanished between the two calls — just skip it.
      if (results[i].error) return;
      for (const [address, meta] of Object.entries(results[i].result || {})) {
        rows.push({ address, label, purpose: meta.purpose || 'unknown' });
      }
    });
  }
  rows.sort((a, b) => (a.label < b.label ? -1 : a.label > b.label ? 1
    : (a.address < b.address ? -1 : 1)));

  // Decorate with getaddressinfo (derivation path; a `reused` field is
  // rendered if the node ever emits one).
  const infoTargets = rows.slice(0, BOOK_INFO_LIMIT);
  if (infoTargets.length > 0) {
    try {
      const infos = await rpc.batch(
        infoTargets.map((r) => ['getaddressinfo', [r.address]]), endpoint());
      infoTargets.forEach((r, i) => {
        if (!infos[i].error) r.info = infos[i].result;
      });
    } catch { /* decoration only */ }
  }
  state.bookRows = rows;
  renderBook();
}

function renderBook() {
  const { refs } = state;
  refs.bookTitle.textContent = `Address book (${fmtInt(state.bookRows.length)})`;
  if (state.bookRows.length === 0) {
    const tr = el('tr');
    const td = el('td', 'muted',
      'no labeled addresses — receive addresses appear here once generated with a label');
    td.colSpan = 5;
    tr.appendChild(td);
    refs.bookBody.replaceChildren(tr);
    return;
  }
  refs.bookBody.replaceChildren(...state.bookRows.map((row) => bookRow(row)));
}

function bookRow(row) {
  const tr = el('tr');
  const addrTd = el('td', 'mono');
  addrTd.appendChild(copyable(row.address, shortId(row.address, 12)));
  if (row.info?.ischange) addrTd.appendChild(pill('change', 'pill-muted'));
  if (row.info?.reused) addrTd.appendChild(pill('reused', 'pill-bad'));
  tr.appendChild(addrTd);

  const labelTd = el('td', 'book-label');
  const labelSpan = el('span', '', row.label);
  labelTd.appendChild(labelSpan);
  tr.appendChild(labelTd);
  tr.appendChild(el('td', '', row.purpose));
  tr.appendChild(el('td', 'mono muted', row.info?.hdkeypath ?? '—'));

  // Inline label edit: swap the label cell to an input + save/cancel.
  const editTd = el('td', 'num');
  const editBtn = el('button', 'btn', 'edit');
  editBtn.type = 'button';
  editBtn.addEventListener('click', () => {
    const input = el('input', 'book-edit');
    input.value = row.label;
    input.setAttribute('aria-label', `New label for ${row.address}`);
    const save = el('button', 'btn', 'save');
    save.type = 'button';
    save.addEventListener('click', async () => {
      save.disabled = true;
      try {
        await rpc.call(...setLabelParams(row.address, input.value.trim()),
          endpoint());
        await refreshBook();
      } catch (e) {
        state.refs.bookError.textContent = rpcErrorMessage(e);
        state.refs.bookError.hidden = false;
        save.disabled = false;
      }
    });
    const cancel = el('button', 'linklike', 'cancel');
    cancel.type = 'button';
    cancel.addEventListener('click', () => renderBook());
    labelTd.replaceChildren(input, save, cancel);
    editTd.replaceChildren();
    input.focus?.();
  });
  editTd.appendChild(editBtn);
  tr.appendChild(editTd);
  return tr;
}
