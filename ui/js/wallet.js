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
  fmtInt, fmtBtc, fmtAge, fmtPct, fmtDuration, fmtTimestamp, shortHash,
  shortId,
} from './format.js';

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
  ['receive', 'Receive'],
  ['history', 'History'],
  ['addresses', 'Address book'],
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
  refreshing: false,
};

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

  state.refs = refs;
  container.replaceChildren(head, refs.disabledCard, refs.emptyCard,
    refs.balancesCard, refs.infoCard, refs.receiveCard, refs.historyCard,
    refs.bookCard);
  renderTabStrip();
  applyMask();
  renderVisibility();
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
  show(refs.receiveCard, 'receive');
  show(refs.historyCard, 'history');
  show(refs.bookCard, 'addresses');
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
  if (state.refs) {
    state.refs.histStamp = null;
    state.refs.receiveResult.replaceChildren();
    state.refs.receiveError.hidden = true;
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
