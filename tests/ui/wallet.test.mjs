// GUI P6a wallet-screen tests (docs/gui-plan.md P6a). Run from the repo
// root:
//
//   node --test tests/ui/
//
// Zero dependencies: a minimal DOM shim plus a stubbed global fetch drive
// the REAL ui/js modules — wallet.js renders against fixture wallet-RPC
// responses, and every request is asserted to POST the exact JSON-RPC
// method/params through the real rpc.js helper AT the exact endpoint
// (base '/' for node-level calls, '/wallet/<name>' for wallet-scoped
// ones). Covered: disabled/empty states, the load picker, selector
// endpoint switching, overview balances + facts, the mask-values toggle,
// receive with the real QR module, history paging + expansion, and the
// address book with inline setlabel. (The fiveam suite covers the Lisp
// side: asset serving, shell wiring, and registered methods; the QR
// encoder itself is vector-tested in qr.test.mjs.)

import test from 'node:test';
import assert from 'node:assert/strict';

// --- minimal DOM shim ---------------------------------------------------

class ClassList {
  constructor(el) { this.el = el; }
  _list() { return this.el.className.split(/\s+/).filter(Boolean); }
  _set(list) { this.el.className = list.join(' '); }
  add(...cs) { this._set([...new Set([...this._list(), ...cs])]); }
  remove(...cs) { this._set(this._list().filter((c) => !cs.includes(c))); }
  contains(c) { return this._list().includes(c); }
  toggle(c, force) {
    const on = force !== undefined ? force : !this.contains(c);
    if (on) this.add(c); else this.remove(c);
    return on;
  }
}

class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.childNodes = [];
    this.className = '';
    this.dataset = {};
    this.hidden = false;
    this.value = '';
    this._text = '';
    this._attrs = {};
    this._listeners = {};
    this.classList = new ClassList(this);
  }
  get children() { return this.childNodes.filter((c) => c instanceof Element); }
  get firstChild() { return this.childNodes[0] ?? null; }
  set textContent(t) { this.childNodes = []; this._text = String(t); }
  get textContent() {
    return this._text + this.childNodes
      .map((c) => (c instanceof Element ? c.textContent : String(c))).join('');
  }
  append(...nodes) { this.childNodes.push(...nodes); }
  appendChild(n) { this.childNodes.push(n); return n; }
  replaceChildren(...nodes) { this._text = ''; this.childNodes = [...nodes]; }
  setAttribute(k, v) { this._attrs[k] = String(v); }
  getAttribute(k) { return this._attrs[k] ?? null; }
  removeAttribute(k) { delete this._attrs[k]; }
  addEventListener(type, fn) { (this._listeners[type] ??= []).push(fn); }
  async dispatch(type, event = {}) {
    event.preventDefault ??= () => {};
    for (const fn of this._listeners[type] ?? []) await fn(event);
  }
  *walk() {
    yield this;
    for (const c of this.children) yield* c.walk();
  }
  find(pred) { for (const n of this.walk()) if (pred(n)) return n; return null; }
  findAll(pred) { return [...this.walk()].filter(pred); }
}

globalThis.document = {
  createElement: (tag) => new Element(tag),
  getElementById: () => null,
};

globalThis.sessionStorage = {
  _m: new Map(),
  getItem(k) { return this._m.has(k) ? this._m.get(k) : null; },
  setItem(k, v) { this._m.set(k, String(v)); },
  removeItem(k) { this._m.delete(k); },
};

// --- stubbed JSON-RPC endpoint -------------------------------------------

// Fixtures mirror what src/rpc/wallet*.lisp emits. A master oldest-first
// tx list backs listtransactions with our node's count/skip semantics
// (page slices are answered oldest-first).
const NOW = Math.floor(Date.now() / 1000);

const TXS = []; // oldest-first
for (let i = 0; i < 28; i += 1) {
  TXS.push({
    address: `tb1qreceive${i}xxxxxxxxxxxxxxxxxxxxxxx`,
    parent_descs: ['wpkh(tpub.../84h/1h/0h/0/*)#aaaaaaaa'],
    category: 'receive',
    amount: 0.001 * (i + 1),
    label: i % 2 === 0 ? 'even' : '',
    vout: 0,
    abandoned: false,
    confirmations: 28 - i,
    blockhash: 'b'.repeat(63) + String(i % 10),
    blockheight: 900000 + i,
    blockindex: 1,
    blocktime: NOW - (28 - i) * 600,
    txid: `${String(i).padStart(2, '0')}${'ab'.repeat(31)}`,
    wtxid: `${String(i).padStart(2, '0')}${'cd'.repeat(31)}`,
    walletconflicts: [],
    mempoolconflicts: [],
    time: NOW - (28 - i) * 600,
    timereceived: NOW - (28 - i) * 600,
    'bip125-replaceable': 'no',
  });
}
// Newest entry: an unconfirmed send with a fee and a conflict.
const SEND_TXID = 'ff'.repeat(32);
const CONFLICT_TXID = 'ee'.repeat(32);
TXS.push({
  address: 'tb1qsendtoxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  category: 'send',
  amount: -0.5,
  fee: -0.0000141,
  vout: 1,
  abandoned: false,
  confirmations: 0,
  trusted: true,
  txid: SEND_TXID,
  wtxid: 'dd'.repeat(32),
  walletconflicts: [CONFLICT_TXID],
  mempoolconflicts: [],
  time: NOW - 60,
  timereceived: NOW - 60,
  'bip125-replaceable': 'yes',
});

function listTransactionsFixture(params) {
  assert.equal(params[0], '*');
  const [, count, skip] = params;
  const newestFirst = [...TXS].reverse().slice(skip, skip + count);
  return newestFirst.reverse(); // RPC answers oldest-first
}

const GETTX = {
  [SEND_TXID]: {
    amount: -0.5,
    fee: -0.0000141,
    confirmations: 0,
    trusted: true,
    txid: SEND_TXID,
    wtxid: 'dd'.repeat(32),
    walletconflicts: [CONFLICT_TXID],
    mempoolconflicts: [],
    time: NOW - 60,
    timereceived: NOW - 60,
    'bip125-replaceable': 'yes',
    details: [],
    hex: '00',
    lastprocessedblock: { hash: 'aa'.repeat(32), height: 900027 },
  },
};

const BALANCES = {
  mine: { trusted: 1.5, untrusted_pending: 0.25, immature: 0.125 },
  lastprocessedblock: { hash: 'aa'.repeat(32), height: 900027 },
};

const WALLETINFO = {
  walletname: 'cold',
  walletversion: 169900,
  format: 'leveldb',
  txcount: 29,
  keypoolsize: 1000,
  keypoolsize_hd_internal: 1000,
  private_keys_enabled: false,
  avoid_reuse: false,
  scanning: { duration: 12, progress: 0.42 },
  descriptors: true,
  external_signer: false,
  blank: false,
  birthtime: NOW - 86400 * 30,
  flags: ['descriptor_wallet', 'disable_private_keys'],
  lastprocessedblock: { hash: 'aa'.repeat(32), height: 900027 },
};

const NEW_ADDRESS = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';

const ADDRINFO = {
  [NEW_ADDRESS]: {
    address: NEW_ADDRESS,
    scriptPubKey: '0014751e76e8199196d454941c45d1b3a323f1433bd6',
    ismine: true,
    solvable: true,
    iswatchonly: false,
    ischange: false,
    hdkeypath: 'm/84h/1h/0h/0/7',
    parent_desc: 'wpkh(tpubDEXAMPLE/84h/1h/0h/0/*)#q3aqm2pf',
    labels: ['tips'],
  },
  tb1qalpha: {
    address: 'tb1qalpha', ismine: true, solvable: true, ischange: false,
    hdkeypath: 'm/84h/1h/0h/0/0', labels: ['alpha'],
  },
  tb1qreused: {
    address: 'tb1qreused', ismine: true, solvable: true, ischange: false,
    hdkeypath: 'm/84h/1h/0h/0/1', reused: true, labels: ['alpha'],
  },
  tb1qelsewhere: {
    address: 'tb1qelsewhere', ismine: false, solvable: false, labels: ['tips'],
  },
};

const fixtures = {
  listwallets: () => ['cold', 'hot'],
  listwalletdir: () => ({ wallets: [{ name: 'cold' }, { name: 'hot' }] }),
  loadwallet: (params) => ({ name: params[0], warnings: [] }),
  getbalances: () => BALANCES,
  getwalletinfo: () => WALLETINFO,
  getblockcount: () => 900027,
  getnewaddress: () => NEW_ADDRESS,
  getaddressinfo: (params) => {
    const info = ADDRINFO[params[0]];
    if (!info) throw { code: -5, message: 'Invalid address' };
    return info;
  },
  listtransactions: listTransactionsFixture,
  gettransaction: (params) => {
    const tx = GETTX[params[0]];
    if (!tx) throw { code: -5, message: 'Invalid or non-wallet transaction id' };
    return tx;
  },
  listlabels: () => ['alpha', 'tips'],
  getaddressesbylabel: (params) => (params[0] === 'alpha'
    ? { tb1qalpha: { purpose: 'receive' }, tb1qreused: { purpose: 'receive' } }
    : { tb1qelsewhere: { purpose: 'send' } }),
  setlabel: () => null,
};

const rpcLog = []; // every { url, method, params } POSTed through rpc.js

globalThis.fetch = async (url, opts) => {
  const payload = JSON.parse(opts.body);
  const requests = Array.isArray(payload) ? payload : [payload];
  const responses = requests.map((r) => {
    rpcLog.push({ url, method: r.method, params: r.params });
    const fn = fixtures[r.method];
    if (!fn) {
      return { jsonrpc: '2.0', id: r.id, result: null,
        error: { code: -32601, message: 'Method not found' } };
    }
    try {
      return { jsonrpc: '2.0', id: r.id, result: fn(r.params ?? []), error: null };
    } catch (e) {
      return { jsonrpc: '2.0', id: r.id, result: null,
        error: { code: e.code ?? -1, message: e.message ?? 'error' } };
    }
  });
  return {
    status: 200,
    ok: true,
    json: async () => (Array.isArray(payload) ? responses : responses[0]),
  };
};

// --- the real modules under test ------------------------------------------

const wallet = await import('../../ui/js/wallet.js');

async function confirmClick(btn) {
  await btn.dispatch('click');
  await btn.dispatch('click');
}

function byAria(container, label) {
  return container.find((n) => n.getAttribute('aria-label') === label);
}

function tbodyRows(card) {
  return card.find((n) => n.tagName === 'TBODY').children;
}

function cellTexts(tr) { return tr.children.map((td) => td.textContent); }

const container = new Element('main');

// --- pure helpers -----------------------------------------------------------

test('walletEndpoint URI-encodes the wallet name', () => {
  assert.equal(wallet.walletEndpoint('cold'), '/wallet/cold');
  assert.equal(wallet.walletEndpoint('my wallet/2'), '/wallet/my%20wallet%2F2');
});

test('bip21Uri: bare address, label URI-encoded when present', () => {
  assert.equal(wallet.bip21Uri('tb1qxyz'), 'bitcoin:tb1qxyz');
  assert.equal(wallet.bip21Uri('tb1qxyz', 'node donations'),
    'bitcoin:tb1qxyz?label=node%20donations');
});

test('address types are the four Core output types, bech32 first (default)', () => {
  assert.deepEqual(wallet.ADDRESS_TYPES,
    ['bech32', 'bech32m', 'p2sh-segwit', 'legacy']);
});

test('history paging params probe one entry beyond the page', () => {
  assert.deepEqual(wallet.historyParams(0), ['listtransactions', ['*', 26, 0]]);
  assert.deepEqual(wallet.historyParams(3), ['listtransactions', ['*', 26, 75]]);
});

test('historyPage: newest-first display order, probe entry dropped', () => {
  const oldestFirst = [{ txid: 'a' }, { txid: 'b' }, { txid: 'c' }];
  const page = wallet.historyPage(oldestFirst, 2);
  assert.deepEqual(page.entries.map((e) => e.txid), ['c', 'b']);
  assert.equal(page.hasMore, true);
  const last = wallet.historyPage(oldestFirst, 3);
  assert.deepEqual(last.entries.map((e) => e.txid), ['c', 'b', 'a']);
  assert.equal(last.hasMore, false);
});

test('unloadedWallets: directory minus loaded, sorted', () => {
  assert.deepEqual(
    wallet.unloadedWallets({ wallets: [{ name: 'b' }, { name: 'a' }, { name: 'c' }] },
      ['c']),
    ['a', 'b']);
  assert.deepEqual(wallet.unloadedWallets(null, []), []);
});

test('write/fetch param seams match the RPC signatures', () => {
  assert.deepEqual(wallet.loadParams('w'), ['loadwallet', ['w']]);
  assert.deepEqual(wallet.newAddressParams('', 'bech32'),
    ['getnewaddress', ['', 'bech32']]);
  assert.deepEqual(wallet.newAddressParams('tips', 'bech32m'),
    ['getnewaddress', ['tips', 'bech32m']]);
  assert.deepEqual(wallet.setLabelParams('tb1q', 'new label'),
    ['setlabel', ['tb1q', 'new label']]);
});

test('mask preference persists in sessionStorage', () => {
  assert.equal(wallet.isMasked(), false);
  wallet.setMasked(true);
  assert.equal(sessionStorage.getItem(wallet.MASK_KEY), '1');
  assert.equal(wallet.isMasked(), true);
  wallet.setMasked(false);
  assert.equal(wallet.isMasked(), false);
});

// --- disabled state (mainnet: wallet RPCs answer -32601) --------------------

test('wallet support disabled renders a clear state, never a broken page', async () => {
  const saved = fixtures.listwallets;
  fixtures.listwallets = () => { throw { code: -32601, message: 'Method not found (wallet support is disabled)' }; };
  await wallet.show(container);
  const card = byAria(container, 'Wallet disabled');
  assert.equal(card.hidden, false);
  assert.match(card.textContent, /Wallet support is disabled on this network/);
  assert.equal(byAria(container, 'No wallet loaded').hidden, true);
  assert.equal(byAria(container, 'Balances').hidden, true);
  const tabs = container.find((n) => n.tagName === 'NAV');
  assert.equal(tabs.hidden, true);
  fixtures.listwallets = saved;
});

// --- empty state + load picker ---------------------------------------------

test('no wallet loaded: empty state with instructions + load picker', async () => {
  fixtures.listwallets = () => [];
  await wallet.refresh();
  const card = byAria(container, 'No wallet loaded');
  assert.equal(card.hidden, false);
  assert.match(card.textContent, /no wallet is loaded/i);
  assert.match(card.textContent, /createwallet/);
  // the picker offers both directory wallets, sorted
  const loadSelect = container.find((n) =>
    n.getAttribute('aria-label') === 'Wallet to load');
  assert.deepEqual(loadSelect.children.map((o) => o.textContent), ['cold', 'hot']);
});

test('loadwallet: armed confirm, exact POST on the base endpoint', async () => {
  const loadSelect = container.find((n) =>
    n.getAttribute('aria-label') === 'Wallet to load');
  loadSelect.value = 'cold';
  const btn = container.find((n) =>
    n.tagName === 'BUTTON' && n.textContent === 'load');
  rpcLog.length = 0;
  await btn.dispatch('click'); // arms only
  assert.equal(btn.textContent, 'confirm load?');
  assert.ok(!rpcLog.some((c) => c.method === 'loadwallet'));
  fixtures.listwallets = () => ['cold']; // the load succeeds server-side
  await btn.dispatch('click'); // acts
  assert.deepEqual(rpcLog.find((c) => c.method === 'loadwallet'),
    { url: '/', method: 'loadwallet', params: ['cold'] });
  // the loaded wallet became the selection, persisted for the tab
  assert.equal(sessionStorage.getItem(wallet.WALLET_KEY), 'cold');
  assert.equal(byAria(container, 'No wallet loaded').hidden, true);
});

// --- overview ----------------------------------------------------------------

test('overview: wallet-scoped batch on /wallet/<name>, balances + facts render', async () => {
  fixtures.listwallets = () => ['cold', 'hot'];
  rpcLog.length = 0;
  await wallet.refresh();
  // node-level list calls ride the base endpoint, wallet data the endpoint
  assert.deepEqual(rpcLog.find((c) => c.method === 'listwallets').url, '/');
  for (const method of ['getbalances', 'getwalletinfo', 'getblockcount']) {
    assert.equal(rpcLog.find((c) => c.method === method).url, '/wallet/cold',
      `${method} must ride /wallet/cold`);
  }
  const balances = byAria(container, 'Balances');
  assert.equal(balances.hidden, false);
  assert.match(balances.textContent, /1\.50000000 BTC/);
  assert.match(balances.textContent, /0\.25000000 BTC/);
  assert.match(balances.textContent, /0\.12500000 BTC/);
  assert.match(balances.textContent, /1\.87500000 BTC/); // total
  assert.match(balances.textContent, /at node tip/); // lastprocessedblock fresh
  const info = byAria(container, 'Wallet info');
  assert.match(info.textContent, /29/); // txcount
  assert.match(info.textContent, /1,000 · 1,000/); // keypool
  assert.match(info.textContent, /disabled \(watch-only\)/);
  assert.match(info.textContent, /42\.00%/); // scanning progress, live
  assert.match(info.textContent, /leveldb · descriptors/);
  // watch-only pill on the header (private_keys_enabled false)
  const pill = container.find((n) => n.textContent === 'watch-only');
  assert.equal(pill.hidden, false);
});

test('stale wallet tip shows a blocks-behind indicator', async () => {
  const saved = fixtures.getblockcount;
  fixtures.getblockcount = () => 900030;
  await wallet.refresh();
  assert.match(byAria(container, 'Balances').textContent, /3 blocks behind/);
  fixtures.getblockcount = saved;
});

test('mask-values toggle blurs amounts and persists', async () => {
  const btn = container.find((n) =>
    n.tagName === 'BUTTON' && n.textContent === 'hide amounts');
  await btn.dispatch('click');
  assert.equal(container.classList.contains('mask-on'), true);
  assert.equal(sessionStorage.getItem(wallet.MASK_KEY), '1');
  assert.equal(btn.textContent, 'show amounts');
  assert.equal(btn.getAttribute('aria-pressed'), 'true');
  // amounts carry the .amt class the mask CSS targets — and never leak
  // through a title attribute
  const amts = container.findAll((n) => n.classList.contains('amt'));
  assert.ok(amts.length >= 4);
  assert.ok(amts.every((n) => n.getAttribute('title') === null));
  await btn.dispatch('click');
  assert.equal(container.classList.contains('mask-on'), false);
  assert.equal(sessionStorage.getItem(wallet.MASK_KEY), null);
});

// --- wallet selector switches every endpoint ---------------------------------

test('selector switch: subsequent wallet RPCs ride the new /wallet/<name>', async () => {
  const select = container.find((n) =>
    n.getAttribute('aria-label') === 'Active wallet');
  assert.deepEqual(select.children.map((o) => o.textContent), ['cold', 'hot']);
  select.value = 'hot';
  rpcLog.length = 0;
  await select.dispatch('change');
  assert.equal(rpcLog.find((c) => c.method === 'getbalances').url, '/wallet/hot');
  assert.equal(sessionStorage.getItem(wallet.WALLET_KEY), 'hot');
});

// --- receive -----------------------------------------------------------------

test('receive: exact getnewaddress POST, QR data URI, derivation info', async () => {
  await wallet.show(container, 'receive');
  const card = byAria(container, 'Receive');
  assert.equal(card.hidden, false);
  assert.equal(byAria(container, 'Balances').hidden, true);
  const label = container.find((n) =>
    n.getAttribute('aria-label') === 'Label for the new address');
  const type = container.find((n) =>
    n.getAttribute('aria-label') === 'Address type');
  assert.deepEqual(type.children.map((o) => o.textContent),
    ['bech32', 'bech32m', 'p2sh-segwit', 'legacy']);
  assert.equal(type.value, 'bech32');
  label.value = 'tips';
  type.value = 'bech32m';
  rpcLog.length = 0;
  const form = card.find((n) => n.tagName === 'FORM');
  await form.dispatch('submit');
  assert.deepEqual(rpcLog.find((c) => c.method === 'getnewaddress'),
    { url: '/wallet/hot', method: 'getnewaddress', params: ['tips', 'bech32m'] });
  assert.deepEqual(rpcLog.find((c) => c.method === 'getaddressinfo'),
    { url: '/wallet/hot', method: 'getaddressinfo', params: [NEW_ADDRESS] });
  // rendered: address text + copy, the QR as an inline SVG data URI, the
  // BIP21 URI with the label, and derivation facts
  assert.match(card.textContent, new RegExp(NEW_ADDRESS));
  const img = card.find((n) => n.tagName === 'IMG');
  assert.ok(img.src.startsWith('data:image/svg+xml,'));
  assert.match(decodeURIComponent(img.src), /<svg xmlns/);
  assert.equal(img.alt, `QR code for bitcoin:${NEW_ADDRESS}?label=tips`);
  assert.match(card.textContent, /m\/84h\/1h\/0h\/0\/7/);
  assert.match(card.textContent, /wpkh\(tpubDEXAMPLE/);
  assert.ok(card.find((n) => n.tagName === 'BUTTON' && n.textContent === 'copy'));
});

test('receive keypool exhaustion surfaces the RPC error', async () => {
  const saved = fixtures.getnewaddress;
  fixtures.getnewaddress = () => { throw { code: -12, message: 'Error: No bech32m addresses available.' }; };
  const card = byAria(container, 'Receive');
  await card.find((n) => n.tagName === 'FORM').dispatch('submit');
  assert.match(card.textContent, /No bech32m addresses available.*RPC error -12/);
  fixtures.getnewaddress = saved;
});

// --- history -------------------------------------------------------------

test('history: newest first, 25 per page, exact paged POSTs', async () => {
  rpcLog.length = 0;
  await wallet.show(container, 'history');
  const card = byAria(container, 'Transaction history');
  assert.equal(card.hidden, false);
  assert.deepEqual(rpcLog.find((c) => c.method === 'listtransactions'),
    { url: '/wallet/hot', method: 'listtransactions', params: ['*', 26, 0] });
  const rows = tbodyRows(card);
  assert.equal(rows.length, 25);
  // newest entry (the unconfirmed send) first
  const first = cellTexts(rows[0]);
  assert.match(first[0], /send/);
  assert.equal(first[1], '-0.50000000 BTC');
  assert.equal(first[2], '0');
  // second row is the newest receive, with its label
  const second = cellTexts(rows[1]);
  assert.match(second[0], /receive/);
  assert.equal(second[1], '0.02800000 BTC');
  assert.equal(second[2], '1');
  // pager: no newer page, an older page exists
  const newer = card.find((n) => n.tagName === 'BUTTON' && n.textContent === '‹ newer');
  const older = card.find((n) => n.tagName === 'BUTTON' && n.textContent === 'older ›');
  assert.equal(newer.disabled, true);
  assert.equal(older.disabled, false);
});

test('history paging: older page skips 25, shows the remainder', async () => {
  const card = byAria(container, 'Transaction history');
  const older = card.find((n) => n.tagName === 'BUTTON' && n.textContent === 'older ›');
  rpcLog.length = 0;
  await older.dispatch('click');
  assert.deepEqual(rpcLog.find((c) => c.method === 'listtransactions'),
    { url: '/wallet/hot', method: 'listtransactions', params: ['*', 26, 25] });
  const rows = tbodyRows(card);
  assert.equal(rows.length, 4); // 29 entries total: 25 + 4
  // oldest entry of all sits at the bottom
  assert.equal(cellTexts(rows[3])[1], '0.00100000 BTC');
  const newer2 = card.find((n) => n.tagName === 'BUTTON' && n.textContent === '‹ newer');
  const older2 = card.find((n) => n.tagName === 'BUTTON' && n.textContent === 'older ›');
  assert.equal(newer2.disabled, false);
  assert.equal(older2.disabled, true);
  await newer2.dispatch('click'); // back to page 0 for the next test
});

test('row expansion: gettransaction detail with fee/conflicts/RBF + explorer links', async () => {
  const card = byAria(container, 'Transaction history');
  const rows = tbodyRows(card);
  rpcLog.length = 0;
  await rows[0].dispatch('click'); // the unconfirmed send
  assert.deepEqual(rpcLog.find((c) => c.method === 'gettransaction'),
    { url: '/wallet/hot', method: 'gettransaction', params: [SEND_TXID] });
  const detailRow = tbodyRows(card)[1]; // inserted right below
  assert.ok(detailRow.classList.contains('tx-detail-row'));
  const text = detailRow.textContent;
  assert.match(text, /-0\.00001410 BTC/); // fee
  assert.match(text, /yes/); // bip125-replaceable
  assert.match(text, /trusted/);
  // walletconflict + explorer permalinks into the existing pages
  const links = detailRow.findAll((n) => n.tagName === 'A');
  assert.ok(links.some((a) => a.href === `#/tx/${SEND_TXID}`));
  assert.ok(links.some((a) => a.href === `#/tx/${CONFLICT_TXID}`));
  // collapse again
  await tbodyRows(card)[0].dispatch('click');
  assert.equal(tbodyRows(card).length, 25);
});

test('confirmed receive rows link their block through the detail panel', async () => {
  const card = byAria(container, 'Transaction history');
  const rows = tbodyRows(card);
  const entryTxid = `27${'ab'.repeat(31)}`; // newest receive (i=27)
  GETTX[entryTxid] = {
    amount: 0.028,
    confirmations: 1,
    txid: entryTxid,
    wtxid: `27${'cd'.repeat(31)}`,
    walletconflicts: [],
    mempoolconflicts: [],
    generated: false,
    blockhash: 'b'.repeat(63) + '7',
    blockheight: 900027,
    blocktime: NOW - 600,
    time: NOW - 600,
    timereceived: NOW - 600,
    'bip125-replaceable': 'no',
    details: [],
    hex: '00',
  };
  await rows[1].dispatch('click');
  const detailRow = tbodyRows(card)[2];
  const links = detailRow.findAll((n) => n.tagName === 'A');
  assert.ok(links.some((a) => a.href === `#/block/${'b'.repeat(63)}7`));
  await tbodyRows(card)[1].dispatch('click'); // collapse
});

// --- address book ----------------------------------------------------------

test('address book: labels resolved per label, purposes + reuse pill', async () => {
  rpcLog.length = 0;
  await wallet.show(container, 'addresses');
  const card = byAria(container, 'Address book');
  assert.equal(card.hidden, false);
  assert.equal(rpcLog.find((c) => c.method === 'listlabels').url, '/wallet/hot');
  const byLabel = rpcLog.filter((c) => c.method === 'getaddressesbylabel');
  assert.deepEqual(byLabel.map((c) => c.params), [['alpha'], ['tips']]);
  assert.ok(byLabel.every((c) => c.url === '/wallet/hot'));
  const rows = tbodyRows(card);
  assert.equal(rows.length, 3);
  // sorted by label, then address
  assert.match(rows[0].textContent, /tb1qalpha/);
  assert.match(rows[0].textContent, /receive/);
  assert.match(rows[0].textContent, /m\/84h\/1h\/0h\/0\/0/);
  assert.match(rows[1].textContent, /tb1qreused/);
  // the reused indicator renders whenever getaddressinfo exposes it
  assert.ok(rows[1].find((n) => n.textContent === 'reused'));
  assert.ok(!rows[0].find((n) => n.textContent === 'reused'));
  assert.match(rows[2].textContent, /tb1qelsewhere/);
  assert.match(rows[2].textContent, /send/);
});

test('inline label edit posts the exact setlabel', async () => {
  const card = byAria(container, 'Address book');
  const rows = tbodyRows(card);
  const edit = rows[0].find((n) => n.tagName === 'BUTTON' && n.textContent === 'edit');
  await edit.dispatch('click');
  const input = rows[0].find((n) => n.tagName === 'INPUT');
  input.value = ' alpha-cold ';
  const save = rows[0].find((n) => n.tagName === 'BUTTON' && n.textContent === 'save');
  rpcLog.length = 0;
  await save.dispatch('click');
  assert.deepEqual(rpcLog.find((c) => c.method === 'setlabel'),
    { url: '/wallet/hot', method: 'setlabel', params: ['tb1qalpha', 'alpha-cold'] });
  // save triggers a book refresh
  assert.ok(rpcLog.some((c) => c.method === 'listlabels'));
});

test('the new-entry form labels an arbitrary (sending) address', async () => {
  const card = byAria(container, 'Address book');
  const addr = container.find((n) =>
    n.getAttribute('aria-label') === 'Address to label');
  const label = container.find((n) => n.getAttribute('aria-label') === 'Label');
  addr.value = ' tb1qelsewhere ';
  label.value = 'exchange';
  rpcLog.length = 0;
  await card.find((n) => n.tagName === 'FORM').dispatch('submit');
  assert.deepEqual(rpcLog.find((c) => c.method === 'setlabel'),
    { url: '/wallet/hot', method: 'setlabel', params: ['tb1qelsewhere', 'exchange'] });
});

// --- poll integration ---------------------------------------------------

test('refresh() is a no-op while the view is hidden', async () => {
  container.hidden = true;
  rpcLog.length = 0;
  await wallet.refresh();
  assert.equal(rpcLog.length, 0);
  container.hidden = false;
});

test('resetWallet drops the view; show() rebuilds from scratch', async () => {
  wallet.resetWallet();
  const fresh = new Element('main');
  await wallet.show(fresh, 'overview');
  assert.equal(byAria(fresh, 'Balances').hidden, false);
  // the stored selection survives the rebuild (sessionStorage, like creds)
  assert.match(byAria(fresh, 'Balances').textContent, /1\.50000000 BTC/);
});
