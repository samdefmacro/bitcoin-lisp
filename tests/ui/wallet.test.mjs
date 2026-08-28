// GUI P6a wallet-screen tests (docs/gui-plan.md P6a). Run from the repo
// root:
//
//   scripts/dev.sh ui-test
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

// Fixtures mirror what src/wallet/*.lisp emits. A master oldest-first
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

// Send-tab fixtures: a broadcast txid, a fee estimate (0.00002 BTC/kvB =
// 2.00 sat/vB), and the two spend RPCs (sendtoaddress -> bare txid string,
// send -> { complete, txid }).
const BROADCAST_TXID = '7c'.repeat(32);
const RECIP_A = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
const RECIP_B = 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7';

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
  estimatesmartfee: (params) => ({ feerate: 0.00002, blocks: params[0] ?? 6 }),
  sendtoaddress: () => BROADCAST_TXID,
  send: () => ({ complete: true, txid: BROADCAST_TXID }),
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

const tick = () => new Promise((r) => setTimeout(r, 0));

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

// --- send: pure param-building + validation ---------------------------------

test('feeModeForRbf tracks the wallet default (economical while signaling RBF)', () => {
  assert.equal(wallet.feeModeForRbf(true), 'economical');
  assert.equal(wallet.feeModeForRbf(false), 'conservative');
});

test('estimateFeeParams: node conf_target + mode', () => {
  assert.deepEqual(wallet.estimateFeeParams(6, true),
    ['estimatesmartfee', [6, 'economical']]);
  assert.deepEqual(wallet.estimateFeeParams(2, false),
    ['estimatesmartfee', [2, 'conservative']]);
});

test('normalizeAmount: canonical decimal string + exact satoshis, rejects junk', () => {
  assert.deepEqual(wallet.normalizeAmount('0.5'),
    { ok: true, value: '0.5', sats: 50000000n });
  assert.deepEqual(wallet.normalizeAmount(' 1 '),
    { ok: true, value: '1', sats: 100000000n });
  assert.deepEqual(wallet.normalizeAmount('0.00000001'),
    { ok: true, value: '0.00000001', sats: 1n });
  // decimal text is forwarded verbatim (no float round-trip)
  assert.equal(wallet.normalizeAmount('0.10000000').value, '0.10000000');
  assert.equal(wallet.normalizeAmount('').ok, false);
  assert.equal(wallet.normalizeAmount('0').ok, false); // zero not allowed
  assert.equal(wallet.normalizeAmount('1.234567891').ok, false); // >8 dp
  assert.equal(wallet.normalizeAmount('1e8').ok, false);
  assert.equal(wallet.normalizeAmount('abc').ok, false);
  assert.equal(wallet.normalizeAmount('21000001').ok, false); // > MAX_MONEY
});

test('validateAddress: bech32 + base58 accepted, garbage rejected', () => {
  assert.equal(wallet.validateAddress(RECIP_A).ok, true);
  assert.equal(wallet.validateAddress('mzBc4XEFSdzCDcTxAgf6EZXgsZWpztRhef').ok, true);
  assert.equal(wallet.validateAddress('2N1LGaGg836mqSQqiuUBLfcyGBhyZbremDX').ok, true);
  assert.equal(wallet.validateAddress('  ').ok, false);
  assert.equal(wallet.validateAddress('tb1q has spaces').ok, false);
  assert.equal(wallet.validateAddress('not-an-address').ok, false);
  assert.equal(wallet.validateAddress('').reason, 'address is required');
});

test('validateRecipients: dedup + per-row errors, cleaned parallel array', () => {
  const good = wallet.validateRecipients([
    { address: RECIP_A, amount: '0.5' },
    { address: RECIP_B, amount: '0.25' },
  ]);
  assert.equal(good.ok, true);
  assert.deepEqual(good.cleaned.map((r) => [r.address, r.amount, r.sats]),
    [[RECIP_A, '0.5', 50000000n], [RECIP_B, '0.25', 25000000n]]);

  const bad = wallet.validateRecipients([
    { address: 'garbage', amount: '0.5' },
    { address: RECIP_A, amount: 'x' },
  ]);
  assert.equal(bad.ok, false);
  assert.deepEqual(bad.cleaned, []);
  assert.ok(bad.errors.some((e) => e.index === 0 && e.field === 'address'));
  assert.ok(bad.errors.some((e) => e.index === 1 && e.field === 'amount'));

  const dup = wallet.validateRecipients([
    { address: RECIP_A, amount: '0.5' },
    { address: RECIP_A, amount: '0.25' },
  ]);
  assert.ok(dup.errors.some((e) => e.reason === 'duplicate address'));
});

test('buildSendCall: single recipient rides sendtoaddress (RBF on, no SFFO)', () => {
  assert.deepEqual(
    wallet.buildSendCall({
      recipients: [{ address: RECIP_A, amount: '0.5' }],
      confTarget: 6, rbf: true, subtractFee: false,
    }),
    ['sendtoaddress',
      [RECIP_A, '0.5', '', '', false, true, 6, 'economical']]);
});

test('buildSendCall: single recipient RBF off + SFFO on flips the positionals', () => {
  assert.deepEqual(
    wallet.buildSendCall({
      recipients: [{ address: RECIP_A, amount: '0.001' }],
      confTarget: 2, rbf: false, subtractFee: true,
    }),
    ['sendtoaddress',
      [RECIP_A, '0.001', '', '', true, false, 2, 'conservative']]);
});

test('buildSendCall: multi recipient rides send with ordered outputs + options', () => {
  assert.deepEqual(
    wallet.buildSendCall({
      recipients: [
        { address: RECIP_A, amount: '0.5' },
        { address: RECIP_B, amount: '0.25' },
      ],
      confTarget: 6, rbf: true, subtractFee: false,
    }),
    ['send',
      [[{ [RECIP_A]: '0.5' }, { [RECIP_B]: '0.25' }], 6, 'economical', null,
        { replaceable: true }]]);
});

test('buildSendCall: multi recipient SFFO subtracts fee from every output index', () => {
  assert.deepEqual(
    wallet.buildSendCall({
      recipients: [
        { address: RECIP_A, amount: '0.5' },
        { address: RECIP_B, amount: '0.25' },
      ],
      confTarget: 12, rbf: false, subtractFee: true,
    }),
    ['send',
      [[{ [RECIP_A]: '0.5' }, { [RECIP_B]: '0.25' }], 12, 'conservative', null,
        { replaceable: false, subtract_fee_from_outputs: [0, 1] }]]);
});

test('sendResultTxid: bare string (sendtoaddress) or { txid } (send)', () => {
  assert.equal(wallet.sendResultTxid('deadbeef'), 'deadbeef');
  assert.equal(wallet.sendResultTxid({ txid: 'cafe', complete: true }), 'cafe');
});

test('fmtSatsBtc: exact 8-decimal BTC from BigInt satoshis', () => {
  assert.equal(wallet.fmtSatsBtc(187500000n), '1.87500000 BTC');
  assert.equal(wallet.fmtSatsBtc(1n), '0.00000001 BTC');
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

// --- send screen ------------------------------------------------------------

test('send: single recipient previews the fee then POSTs sendtoaddress', async () => {
  await wallet.show(container, 'send');
  const card = byAria(container, 'Send');
  assert.equal(card.hidden, false);
  assert.equal(byAria(container, 'Balances').hidden, true);
  // a single blank recipient row to start; the four Core defaults are set
  byAria(container, 'Recipient 1 address').value = RECIP_A;
  byAria(container, 'Recipient 1 amount (BTC)').value = '0.5';
  const form = card.find((n) => n.tagName === 'FORM');

  rpcLog.length = 0;
  await form.dispatch('submit'); // review step prices the spend
  // estimatesmartfee is a NODE method: base endpoint, mode tracks RBF (on)
  assert.deepEqual(rpcLog.find((c) => c.method === 'estimatesmartfee'),
    { url: '/', method: 'estimatesmartfee', params: [6, 'economical'] });
  assert.ok(!rpcLog.some((c) => c.method === 'sendtoaddress')); // not yet
  assert.match(card.textContent, /Review send/);
  assert.match(card.textContent, /2\.00 sat\/vB/); // feerate preview

  const confirm = card.find((n) =>
    n.tagName === 'BUTTON' && n.textContent === 'confirm and send');
  rpcLog.length = 0;
  await confirm.dispatch('click');
  assert.deepEqual(rpcLog.find((c) => c.method === 'sendtoaddress'),
    { url: '/wallet/hot', method: 'sendtoaddress',
      params: [RECIP_A, '0.5', '', '', false, true, 6, 'economical'] });
  // broadcast result surfaces the txid + an explorer permalink
  assert.match(card.textContent, /Transaction broadcast/);
  assert.ok(card.findAll((n) => n.tagName === 'A')
    .some((a) => a.href === `#/tx/${BROADCAST_TXID}`));
});

test('send: adding a recipient POSTs the ordered multi-output send shape', async () => {
  const card = byAria(container, 'Send');
  // the prior broadcast reset the form to one blank recipient
  byAria(container, 'Recipient 1 address').value = RECIP_A;
  byAria(container, 'Recipient 1 amount (BTC)').value = '0.5';
  const addBtn = card.find((n) =>
    n.tagName === 'BUTTON' && n.textContent === '+ add recipient');
  await addBtn.dispatch('click');
  byAria(container, 'Recipient 2 address').value = RECIP_B;
  byAria(container, 'Recipient 2 amount (BTC)').value = '0.25';

  const form = card.find((n) => n.tagName === 'FORM');
  await form.dispatch('submit');
  const confirm = card.find((n) =>
    n.tagName === 'BUTTON' && n.textContent === 'confirm and send');
  rpcLog.length = 0;
  await confirm.dispatch('click');
  // two recipients switch the call to `send` with an order-preserving
  // array-of-objects outputs list on the wallet endpoint
  assert.deepEqual(rpcLog.find((c) => c.method === 'send'),
    { url: '/wallet/hot', method: 'send',
      params: [[{ [RECIP_A]: '0.5' }, { [RECIP_B]: '0.25' }], 6, 'economical',
        null, { replaceable: true }] });
  assert.ok(!rpcLog.some((c) => c.method === 'sendtoaddress'));
});

test('send: RBF off + subtract-fee flip the sendtoaddress positionals', async () => {
  const card = byAria(container, 'Send');
  byAria(container, 'Recipient 1 address').value = RECIP_A;
  byAria(container, 'Recipient 1 amount (BTC)').value = '0.001';
  byAria(container, 'Signal replace-by-fee (BIP125)').checked = false;
  byAria(container, 'Subtract fee from outputs').checked = true;
  byAria(container, 'Confirmation target (blocks)').value = '2';

  const form = card.find((n) => n.tagName === 'FORM');
  rpcLog.length = 0;
  await form.dispatch('submit');
  // preview mode follows RBF-off -> conservative, at the chosen target
  assert.deepEqual(rpcLog.find((c) => c.method === 'estimatesmartfee'),
    { url: '/', method: 'estimatesmartfee', params: [2, 'conservative'] });
  const confirm = card.find((n) =>
    n.tagName === 'BUTTON' && n.textContent === 'confirm and send');
  rpcLog.length = 0;
  await confirm.dispatch('click');
  assert.deepEqual(rpcLog.find((c) => c.method === 'sendtoaddress'),
    { url: '/wallet/hot', method: 'sendtoaddress',
      params: [RECIP_A, '0.001', '', '', true, false, 2, 'conservative'] });
});

test('send: client-side validation blocks a bad destination before any RPC', async () => {
  const card = byAria(container, 'Send');
  byAria(container, 'Signal replace-by-fee (BIP125)').checked = true;
  byAria(container, 'Subtract fee from outputs').checked = false;
  byAria(container, 'Recipient 1 address').value = 'definitely-not-an-address';
  byAria(container, 'Recipient 1 amount (BTC)').value = '0.5';

  const form = card.find((n) => n.tagName === 'FORM');
  rpcLog.length = 0;
  await form.dispatch('submit');
  // no fee estimate, no spend — the row error renders instead
  assert.equal(rpcLog.length, 0);
  const err = card.find((n) => n.classList.contains('error-text') && !n.hidden);
  assert.match(err.textContent, /recipient 1 address/);
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

// --- security tab: lifecycle + encryption (gui-plan P6d) -------------------
//
// Ported from Core's Qt dialogs (gui-plan §5.1). These assert the two things
// that make the port worth doing: the state derivation takes BOTH
// getwalletinfo fields with NoKeys dominating, and signing borrows an unlock
// rather than leaving the wallet open (Core's UnlockContext).

const crypt = await import('../../ui/js/wallet-crypt.js');
const rpcmod = await import('../../ui/js/rpc.js');

// Encrypted-wallet variants of the fixture. `private_keys_enabled` is true
// here — the default WALLETINFO is watch-only, which is precisely the case
// that must show NO encryption controls.
const ENC_INFO = (unlockedUntil) => ({
  ...WALLETINFO,
  walletname: 'cold',
  private_keys_enabled: true,
  ...(unlockedUntil === undefined ? {} : { unlocked_until: unlockedUntil }),
});

async function securityTab(info) {
  fixtures.getwalletinfo = () => info;
  // Pin the selection: earlier tests — and the restore/create cases below —
  // move it, while every assertion here is on the /wallet/<name> endpoint.
  sessionStorage.setItem(wallet.WALLET_KEY, 'cold');
  wallet.resetWallet();
  await wallet.show(container, 'security');
  await wallet.refresh();
  return byAria(container, 'Security');
}

function buttonByText(card, text) {
  return card.find((n) => n.tagName === 'BUTTON' && n.textContent === text);
}

test('encryptionState: four Core states, NoKeys dominates', () => {
  // walletmodel.h:67-73 — the order is load-bearing.
  assert.equal(crypt.encryptionState(undefined), 'unknown');
  assert.equal(crypt.encryptionState({ private_keys_enabled: true }), 'unencrypted');
  assert.equal(crypt.encryptionState(
    { private_keys_enabled: true, unlocked_until: 0 }), 'locked');
  assert.equal(crypt.encryptionState(
    { private_keys_enabled: true, unlocked_until: 1786955402 }), 'unlocked');
  // watch-only wins even when the wallet somehow carries encryption keys —
  // Core hits this with wallets that old bugs left "encrypted" but inert.
  assert.equal(crypt.encryptionState(
    { private_keys_enabled: false, unlocked_until: 0 }), 'no-keys');
  // "unencrypted" is the ABSENCE of the key, never 0 (0 means locked).
  assert.equal(crypt.encryptionState({ private_keys_enabled: true }), 'unencrypted');
  assert.equal(crypt.isEncrypted('locked'), true);
  assert.equal(crypt.isEncrypted('unlocked'), true);
  assert.equal(crypt.isEncrypted('unencrypted'), false);
  assert.equal(crypt.isEncrypted('no-keys'), false);
});

test('unlockCountdown: floors at zero, never negative', () => {
  const nowMs = 1_000_000_000_000;
  const now = Math.floor(nowMs / 1000);
  assert.equal(crypt.unlockSecondsLeft({ unlocked_until: now + 90 }, nowMs), 90);
  assert.equal(crypt.unlockCountdown({ unlocked_until: now + 90 }, nowMs), '1m 30s');
  assert.equal(crypt.unlockCountdown({ unlocked_until: now + 45 }, nowMs), '45s');
  assert.equal(crypt.unlockCountdown({ unlocked_until: now + 7200 }, nowMs), '2h 00m');
  // an elapsed deadline is 0, not a negative countdown
  assert.equal(crypt.unlockSecondsLeft({ unlocked_until: now - 10 }, nowMs), 0);
  assert.equal(crypt.unlockCountdown({ unlocked_until: 0 }, nowMs), '');
});

test('passphrase validation: Core\'s exact mismatch string, frontend-only', () => {
  assert.equal(crypt.validatePassphrasePair('a', 'a'), null);
  assert.equal(crypt.validatePassphrasePair('', ''), 'Enter a passphrase.');
  assert.equal(crypt.validatePassphrasePair('a', 'b'),
    'The supplied passphrases do not match.');
  assert.equal(crypt.validateTimeout('60'), null);
  assert.equal(crypt.validateTimeout('-1'), 'Timeout cannot be negative.');
  assert.equal(crypt.validateTimeout('soon'), 'Timeout must be an integer.');
});

test('createParams: empty passphrase is null, not the empty string', () => {
  // An empty string is a DIFFERENT request to the node (it warns "wallet will
  // not be encrypted"); sending it by accident would be a silent behaviour
  // change, so the builder must distinguish them.
  assert.deepEqual(crypt.createParams({ name: 'w' }), ['w', false, false, null, false]);
  assert.deepEqual(crypt.createParams({ name: 'w', passphrase: 'p' }),
    ['w', false, false, 'p', false]);
  assert.deepEqual(
    crypt.createParams({ name: 'w', disablePrivateKeys: true, blank: true }),
    ['w', true, true, null, false]);
  // the node refuses this combination with -4; the form says so first
  assert.match(crypt.validateCreate(
    { name: 'w', disablePrivateKeys: true, passphrase: 'p', confirm: 'p' }),
  /private keys are disabled/);
  assert.match(crypt.validateCreate({ name: '../evil' }), /Invalid wallet name/);
  assert.equal(crypt.validateCreate({ name: 'ok' }), null);
});

test('withUnlocked: borrows the unlock and hands it back', async () => {
  // Core's UnlockContext (walletmodel.cpp:428-446).
  const calls = [];
  const mk = (stateSeq, promptResult = true) => {
    let i = 0;
    return {
      state: () => stateSeq[Math.min(i, stateSeq.length - 1)],
      prompt: async () => { calls.push('prompt'); i++; return promptResult; },
      lock: async () => { calls.push('lock'); },
    };
  };
  const locked = { private_keys_enabled: true, unlocked_until: 0 };
  const unlocked = { private_keys_enabled: true, unlocked_until: 99 };

  // unencrypted: runs straight through, and must NOT lock afterwards
  calls.length = 0;
  assert.equal(await crypt.withUnlocked(mk([{ private_keys_enabled: true }]),
    async () => 'ran'), 'ran');
  assert.deepEqual(calls, []);

  // watch-only: same — relocking a watch-only wallet is Core's documented bug case
  calls.length = 0;
  assert.equal(await crypt.withUnlocked(mk([{ private_keys_enabled: false }]),
    async () => 'ran'), 'ran');
  assert.deepEqual(calls, []);

  // already unlocked: runs, and does NOT relock (it was not locked to begin with)
  calls.length = 0;
  assert.equal(await crypt.withUnlocked(mk([unlocked]), async () => 'ran'), 'ran');
  assert.deepEqual(calls, []);

  // locked: prompts, runs, then relocks — the whole point
  calls.length = 0;
  assert.equal(await crypt.withUnlocked(mk([locked, unlocked]),
    async () => { calls.push('run'); return 'ran'; }), 'ran');
  assert.deepEqual(calls, ['prompt', 'run', 'lock']);

  // cancelled: THROWS rather than returning a sentinel a caller could mistake
  // for a result, never runs fn, and does not relock a wallet it never unlocked
  calls.length = 0;
  await assert.rejects(
    () => crypt.withUnlocked(mk([locked, locked], false),
      async () => { calls.push('run'); }),
    (e) => e instanceof crypt.UnlockCancelled);
  assert.deepEqual(calls, ['prompt']);

  // relocks even when the operation throws
  calls.length = 0;
  await assert.rejects(() => crypt.withUnlocked(mk([locked, unlocked]),
    async () => { throw new Error('boom'); }));
  assert.deepEqual(calls, ['prompt', 'lock']);
});

test('security tab: watch-only offers no encryption controls', async () => {
  const card = await securityTab({ ...WALLETINFO, private_keys_enabled: false });
  assert.equal(card.hidden, false);
  assert.match(card.textContent, /watch-only/);
  for (const label of ['encrypt wallet…', 'unlock…', 'lock now', 'change passphrase…']) {
    assert.equal(buttonByText(card, label), null,
      `watch-only must not offer "${label}"`);
  }
  // backup still applies to a watch-only wallet
  assert.ok(buttonByText(card, 'back up…'));
});

test('security tab: unencrypted offers encrypt, not unlock', async () => {
  const card = await securityTab(ENC_INFO(undefined));
  assert.match(card.textContent, /not encrypted/);
  assert.ok(buttonByText(card, 'encrypt wallet…'));
  assert.equal(buttonByText(card, 'unlock…'), null);
  assert.equal(buttonByText(card, 'change passphrase…'), null);
});

test('security tab: locked offers unlock + change, not lock', async () => {
  const card = await securityTab(ENC_INFO(0));
  assert.match(card.textContent, /locked/);
  assert.ok(buttonByText(card, 'unlock…'));
  assert.ok(buttonByText(card, 'change passphrase…'));
  assert.equal(buttonByText(card, 'lock now'), null);
  assert.equal(buttonByText(card, 'encrypt wallet…'), null);
});

test('security tab: unlocked shows the countdown and offers lock', async () => {
  const until = Math.floor(Date.now() / 1000) + 300;
  const card = await securityTab(ENC_INFO(until));
  assert.match(card.textContent, /unlocked/);
  assert.match(card.textContent, /relocks in/);
  assert.ok(buttonByText(card, 'lock now'));
  assert.equal(buttonByText(card, 'unlock…'), null);
});

test('encryptwallet: exact POST, and the mismatch never reaches the node', async () => {
  const card = await securityTab(ENC_INFO(undefined));
  await buttonByText(card, 'encrypt wallet…').dispatch('click');
  const pass = byAria(container, 'New passphrase');
  const confirm = byAria(container, 'Confirm new passphrase');
  const form = byAria(container, 'Encrypt wallet');

  // Core warns about BOTH losing the passphrase and the stale backup.
  assert.match(form.textContent, /LOSE ALL OF YOUR BITCOINS/);
  assert.match(form.textContent, /new HD seed/);

  // mismatch: refused client-side, zero RPCs
  pass.value = 'hunter2';
  confirm.value = 'hunter3';
  rpcLog.length = 0;
  await form.dispatch('submit');
  assert.ok(!rpcLog.some((c) => c.method === 'encryptwallet'));
  assert.match(byAria(container, 'Security').textContent,
    /The supplied passphrases do not match\./);

  // matching: exact POST on the wallet endpoint
  confirm.value = 'hunter2';
  fixtures.encryptwallet = () => 'wallet encrypted; The keypool has been flushed'
    + ' and a new HD seed was generated. You need to make a new backup with the'
    + ' backupwallet RPC.';
  fixtures.getwalletinfo = () => ENC_INFO(0); // the node comes back LOCKED
  rpcLog.length = 0;
  await form.dispatch('submit');
  assert.deepEqual(rpcLog.find((c) => c.method === 'encryptwallet'),
    { url: '/wallet/cold', method: 'encryptwallet', params: ['hunter2'] });
  // the instruction string is surfaced, not swallowed
  assert.match(byAria(container, 'Security').textContent, /make a new backup/);
  // and the passphrase fields were dropped
  assert.equal(pass.value, '');
});

test('walletpassphrase: exact POST including the timeout', async () => {
  const card = await securityTab(ENC_INFO(0));
  await buttonByText(card, 'unlock…').dispatch('click');
  const pass = byAria(container, 'Passphrase');
  const timeout = byAria(container, 'Unlock for');
  assert.equal(timeout.value, String(crypt.DEFAULT_UNLOCK_TIMEOUT));
  pass.value = 'hunter2';
  timeout.value = '900';
  fixtures.walletpassphrase = () => null;
  fixtures.getwalletinfo = () => ENC_INFO(Math.floor(Date.now() / 1000) + 900);
  rpcLog.length = 0;
  await byAria(container, 'Unlock wallet').dispatch('submit');
  assert.deepEqual(rpcLog.find((c) => c.method === 'walletpassphrase'),
    { url: '/wallet/cold', method: 'walletpassphrase', params: ['hunter2', 900] });
  assert.equal(pass.value, '');
});

test('walletpassphrase: a -14 from the node surfaces verbatim', async () => {
  const card = await securityTab(ENC_INFO(0));
  await buttonByText(card, 'unlock…').dispatch('click');
  byAria(container, 'Passphrase').value = 'wrong';
  fixtures.walletpassphrase = () => {
    throw { code: -14, message: 'Error: The wallet passphrase entered was incorrect.' };
  };
  await byAria(container, 'Unlock wallet').dispatch('submit');
  const text = byAria(container, 'Security').textContent;
  assert.match(text, /The wallet passphrase entered was incorrect/);
  assert.match(text, /RPC error -14/);
  // the panel stays open so the user can retry without re-navigating
  assert.ok(byAria(container, 'Unlock wallet'));
});

test('walletpassphrasechange + walletlock: exact POSTs', async () => {
  const card = await securityTab(ENC_INFO(0));
  await buttonByText(card, 'change passphrase…').dispatch('click');
  byAria(container, 'Current passphrase').value = 'old';
  byAria(container, 'New passphrase').value = 'new';
  byAria(container, 'Confirm new passphrase').value = 'new';
  fixtures.walletpassphrasechange = () => null;
  rpcLog.length = 0;
  await byAria(container, 'Change passphrase').dispatch('submit');
  assert.deepEqual(rpcLog.find((c) => c.method === 'walletpassphrasechange'),
    { url: '/wallet/cold', method: 'walletpassphrasechange', params: ['old', 'new'] });

  const unlockedCard = await securityTab(
    ENC_INFO(Math.floor(Date.now() / 1000) + 300));
  fixtures.walletlock = () => null;
  fixtures.getwalletinfo = () => ENC_INFO(0);
  rpcLog.length = 0;
  await buttonByText(unlockedCard, 'lock now').dispatch('click');
  assert.deepEqual(rpcLog.find((c) => c.method === 'walletlock'),
    { url: '/wallet/cold', method: 'walletlock', params: [] });
});

test('backupwallet / restorewallet: node-side paths, correct endpoints', async () => {
  const card = await securityTab(ENC_INFO(0));
  await buttonByText(card, 'back up…').dispatch('click');
  const form = byAria(container, 'Back up wallet');
  // the path is on the node, which is easy to get wrong through a tunnel
  assert.match(form.textContent, /machine running the node/);
  byAria(container, 'Backup destination path').value = '/data/backup.dump';
  fixtures.backupwallet = () => null;
  rpcLog.length = 0;
  await form.dispatch('submit');
  assert.deepEqual(rpcLog.find((c) => c.method === 'backupwallet'),
    { url: '/wallet/cold', method: 'backupwallet', params: ['/data/backup.dump'] });

  const card2 = await securityTab(ENC_INFO(0));
  await buttonByText(card2, 'restore…').dispatch('click');
  byAria(container, 'Restored wallet name').value = 'restored';
  byAria(container, 'Backup file path').value = '/data/backup.dump';
  fixtures.restorewallet = (params) => ({ name: params[0], warnings: [] });
  fixtures.listwallets = () => ['cold', 'hot', 'restored'];
  rpcLog.length = 0;
  await byAria(container, 'Restore wallet from backup').dispatch('submit');
  // restorewallet is NODE-level: it rides the base endpoint, not /wallet/<name>
  assert.deepEqual(rpcLog.find((c) => c.method === 'restorewallet'),
    { url: '/', method: 'restorewallet',
      params: ['restored', '/data/backup.dump'] });
});

test('createwallet: positional params on the base endpoint', async () => {
  fixtures.listwallets = () => ['cold', 'hot'];
  const card = await securityTab(ENC_INFO(0));
  await buttonByText(card, 'create wallet…').dispatch('click');
  const form = byAria(container, 'Create wallet');
  byAria(container, 'New wallet name').value = 'fresh';
  byAria(container, 'New wallet passphrase (optional)').value = 'pw';
  byAria(container, 'Confirm new wallet passphrase').value = 'pw';
  fixtures.createwallet = (params) => ({ name: params[0], warnings: [] });
  fixtures.listwallets = () => ['cold', 'hot', 'fresh'];
  rpcLog.length = 0;
  await form.dispatch('submit');
  assert.deepEqual(rpcLog.find((c) => c.method === 'createwallet'),
    { url: '/', method: 'createwallet',
      params: ['fresh', false, false, 'pw', false] });
});

test('createwallet: watch-only + passphrase is refused before any RPC', async () => {
  fixtures.listwallets = () => ['cold', 'hot'];
  const card = await securityTab(ENC_INFO(0));
  await buttonByText(card, 'create wallet…').dispatch('click');
  byAria(container, 'New wallet name').value = 'nope';
  byAria(container, 'New wallet passphrase (optional)').value = 'pw';
  byAria(container, 'Confirm new wallet passphrase').value = 'pw';
  byAria(container, 'Watch-only (disable private keys)').checked = true;
  rpcLog.length = 0;
  await byAria(container, 'Create wallet').dispatch('submit');
  assert.ok(!rpcLog.some((c) => c.method === 'createwallet'));
  assert.match(byAria(container, 'Security').textContent, /private keys are disabled/);
});

test('show-passphrase toggle flips every field in the panel at once', async () => {
  const card = await securityTab(ENC_INFO(undefined));
  await buttonByText(card, 'encrypt wallet…').dispatch('click');
  const pass = byAria(container, 'New passphrase');
  const confirm = byAria(container, 'Confirm new passphrase');
  assert.equal(pass.type, 'password');
  const toggle = byAria(container, 'Show passphrase');
  await toggle.dispatch('click');
  assert.equal(pass.type, 'text');
  assert.equal(confirm.type, 'text');
  await toggle.dispatch('click');
  assert.equal(pass.type, 'password');
  assert.equal(confirm.type, 'password');
});

test('send on a LOCKED wallet: prompts, signs, then relocks', async () => {
  // The whole reason UnlockContext is ported rather than a retry-on--13 loop.
  // Compose a spend while locked: the page must raise the unlock panel, send
  // only after the unlock lands, and put the wallet BACK to locked afterwards.
  fixtures.listwallets = () => ['cold', 'hot'];
  sessionStorage.setItem(wallet.WALLET_KEY, 'cold');
  wallet.resetWallet();
  let locked = true;
  fixtures.getwalletinfo = () => ENC_INFO(locked ? 0 : Math.floor(Date.now() / 1000) + 300);
  fixtures.walletpassphrase = () => { locked = false; return null; };
  fixtures.walletlock = () => { locked = true; return null; };

  await wallet.show(container, 'send');
  await wallet.refresh();
  byAria(container, 'Recipient 1 address').value = RECIP_A;
  byAria(container, 'Recipient 1 amount (BTC)').value = '0.5';
  const sendCard = byAria(container, 'Send');
  await sendCard.find((n) => n.tagName === 'FORM').dispatch('submit');
  rpcLog.length = 0;

  // Kick off the confirm; it parks on the unlock prompt rather than sending.
  const confirm = buttonByText(sendCard, 'confirm and send');
  const sending = confirm.dispatch('click');
  await tick();
  assert.ok(!rpcLog.some((c) => c.method === 'sendtoaddress'),
    'must not sign while the wallet is locked');
  const unlockForm = byAria(container, 'Unlock wallet');
  assert.ok(unlockForm, 'the unlock panel must be raised');

  byAria(container, 'Passphrase').value = 'hunter2';
  await unlockForm.dispatch('submit');
  await sending;

  const order = rpcLog.filter((c) =>
    ['walletpassphrase', 'sendtoaddress', 'walletlock'].includes(c.method))
    .map((c) => c.method);
  assert.deepEqual(order, ['walletpassphrase', 'sendtoaddress', 'walletlock'],
    'unlock -> sign -> relock, in that order');
  assert.equal(locked, true, 'the wallet must be locked again afterwards');
});

test('send on an UNLOCKED wallet does not relock it afterwards', async () => {
  // The context relocks IFF it was locked to begin with (Core: relock =
  // was_locked). A wallet the user unlocked for a session must stay unlocked.
  fixtures.listwallets = () => ['cold', 'hot'];
  sessionStorage.setItem(wallet.WALLET_KEY, 'cold');
  wallet.resetWallet();
  fixtures.getwalletinfo = () => ENC_INFO(Math.floor(Date.now() / 1000) + 300);
  await wallet.show(container, 'send');
  await wallet.refresh();
  byAria(container, 'Recipient 1 address').value = RECIP_A;
  byAria(container, 'Recipient 1 amount (BTC)').value = '0.5';
  const sendCard = byAria(container, 'Send');
  await sendCard.find((n) => n.tagName === 'FORM').dispatch('submit');
  rpcLog.length = 0;
  await buttonByText(sendCard, 'confirm and send').dispatch('click');
  assert.ok(rpcLog.some((c) => c.method === 'sendtoaddress'));
  assert.ok(!rpcLog.some((c) => c.method === 'walletlock'),
    'an already-unlocked wallet must not be relocked by the send');
});

test('unlock prompt returns you to the tab you came from', async () => {
  // Qt raises a modal over the current view and returns to it; we move to
  // the Security tab to show the panel, so the trip back is owed.
  fixtures.listwallets = () => ['cold', 'hot'];
  sessionStorage.setItem(wallet.WALLET_KEY, 'cold');
  wallet.resetWallet();
  let locked = true;
  fixtures.getwalletinfo = () => ENC_INFO(locked ? 0 : Math.floor(Date.now() / 1000) + 300);
  fixtures.walletpassphrase = () => { locked = false; return null; };
  fixtures.walletlock = () => { locked = true; return null; };

  await wallet.show(container, 'send');
  await wallet.refresh();
  byAria(container, 'Recipient 1 address').value = RECIP_A;
  byAria(container, 'Recipient 1 amount (BTC)').value = '0.5';
  const sendCard = byAria(container, 'Send');
  await sendCard.find((n) => n.tagName === 'FORM').dispatch('submit');
  const sending = buttonByText(sendCard, 'confirm and send').dispatch('click');
  await tick();
  // parked on Security while the prompt is up
  assert.equal(byAria(container, 'Security').hidden, false);
  byAria(container, 'Passphrase').value = 'hunter2';
  await byAria(container, 'Unlock wallet').dispatch('submit');
  await sending;
  // ...and back on Send, with the broadcast result visible there
  assert.equal(byAria(container, 'Send').hidden, false);
  assert.equal(byAria(container, 'Security').hidden, true);
});

test('cancelling the unlock prompt aborts the send and says so', async () => {
  // The cancel path throws UnlockCancelled rather than returning a sentinel a
  // caller could mistake for a result; the send's existing catch renders it.
  fixtures.listwallets = () => ['cold', 'hot'];
  sessionStorage.setItem(wallet.WALLET_KEY, 'cold');
  wallet.resetWallet();
  fixtures.getwalletinfo = () => ENC_INFO(0); // stays locked
  await wallet.show(container, 'send');
  await wallet.refresh();
  byAria(container, 'Recipient 1 address').value = RECIP_A;
  byAria(container, 'Recipient 1 amount (BTC)').value = '0.5';
  const sendCard = byAria(container, 'Send');
  await sendCard.find((n) => n.tagName === 'FORM').dispatch('submit');
  rpcLog.length = 0;
  const sending = buttonByText(sendCard, 'confirm and send').dispatch('click');
  await tick();
  // dismiss the prompt
  await buttonByText(byAria(container, 'Security'), 'cancel').dispatch('click');
  await sending;
  assert.ok(!rpcLog.some((c) => c.method === 'sendtoaddress'),
    'a cancelled unlock must not send');
  assert.ok(!rpcLog.some((c) => c.method === 'walletlock'),
    'nothing was unlocked, so nothing should be relocked');
  // back on Send, with the cancellation explained rather than a raw -13
  assert.equal(byAria(container, 'Send').hidden, false);
  assert.match(byAria(container, 'Send').textContent, /Cancelled — the wallet is locked/);
});

// --- PSBT panel + fee bump (gui-plan P6c) ---------------------------------
//
// Ported from Core's psbtoperationsdialog; the pure half asserts the status
// state machine and the button rules verbatim, the wired half asserts the
// exact RPCs and that signing goes through the same unlock gate as any other
// signing path.

const psbtlib = await import('../../ui/js/wallet-psbt.js');

const PSBT_B64 = 'cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////';
const PSBT_SIGNED = `${PSBT_B64}AQ==`;
const PSBT_IN_ADDR = 'tb1qalpha';
const PSBT_OUT_ADDR = 'tb1qelsewhere';   // in ADDRINFO, ismine:false

const DECODED = {
  tx: {
    vin: [{ txid: 'ab'.repeat(32), vout: 0 }],
    vout: [
      { value: 0.4, scriptPubKey: { address: PSBT_OUT_ADDR, hex: '0014751e' } },
      { value: 0.0999, scriptPubKey: { address: 'tb1qalpha', hex: '0014aaaa' } },
    ],
  },
  inputs: [{ witness_utxo: { amount: 0.5, scriptPubKey: { address: PSBT_IN_ADDR } } }],
  outputs: [{}, {}],
};

const ANALYSIS_NEEDS_SIG = {
  inputs: [{ has_utxo: true, is_final: false, next: 'signer' }],
  fee: 0.0001,
  next: 'signer',
};
const ANALYSIS_COMPLETE = {
  inputs: [{ has_utxo: true, is_final: true, next: 'finalizer' }],
  fee: 0.0001,
  next: 'finalizer',
};

async function psbtTab(analysis, { walletinfo = ENC_INFO(undefined), complete } = {}) {
  fixtures.listwallets = () => ['cold', 'hot'];
  fixtures.getwalletinfo = () => walletinfo;
  fixtures.decodepsbt = () => DECODED;
  fixtures.analyzepsbt = () => analysis;
  // Core fills the PSBT before analysing it; the fill is a no-op here.
  fixtures.walletprocesspsbt = (params) => ({ psbt: params[0], complete: false });
  // Completeness is probed with finalizepsbt, not inferred from the role.
  fixtures.finalizepsbt = () => ({
    complete: complete ?? (analysis === ANALYSIS_COMPLETE),
  });
  sessionStorage.setItem(wallet.WALLET_KEY, 'cold');
  wallet.resetWallet();
  await wallet.show(container, 'psbt');
  await wallet.refresh();
  byAria(container, 'Base64 PSBT').value = PSBT_B64;
  await byAria(container, 'PSBT').find((n) => n.tagName === 'FORM').dispatch('submit');
  return byAria(container, 'PSBT');
}

test('psbtStatus: Core\'s state machine, including the signer sub-cases', () => {
  const ok = { hasWallet: true, privateKeysDisabled: false, couldSign: 1 };
  // psbtoperationsdialog.cpp:262-296, verbatim strings.
  assert.deepEqual(psbtlib.psbtStatus({ next: 'updater' }, ok),
    { text: 'Transaction is missing some information about inputs.', level: 'warn' });
  assert.deepEqual(psbtlib.psbtStatus({ next: 'finalizer' }, ok),
    { text: 'Transaction is fully signed and ready for broadcast.', level: 'info' });
  assert.deepEqual(psbtlib.psbtStatus({ next: 'extractor' }, ok),
    { text: 'Transaction is fully signed and ready for broadcast.', level: 'info' });
  assert.deepEqual(psbtlib.psbtStatus({ next: 'creator' }, ok),
    { text: 'Transaction status is unknown.', level: 'err' });

  // the signer sub-cases are the useful part: "needs signatures" reads very
  // differently once you know THIS wallet can never supply them
  assert.deepEqual(psbtlib.psbtStatus({ next: 'signer' }, ok),
    { text: 'Transaction still needs signature(s).', level: 'info' });
  assert.match(psbtlib.psbtStatus({ next: 'signer' },
    { ...ok, hasWallet: false }).text, /But no wallet is loaded/);
  assert.match(psbtlib.psbtStatus({ next: 'signer' },
    { ...ok, privateKeysDisabled: true }).text, /cannot sign transactions/);
  assert.match(psbtlib.psbtStatus({ next: 'signer' },
    { ...ok, couldSign: 0 }).text, /does not have the right keys/);
  // all three degrade INFO -> WARN
  for (const over of [{ hasWallet: false }, { privateKeysDisabled: true }, { couldSign: 0 }]) {
    assert.equal(psbtlib.psbtStatus({ next: 'signer' }, { ...ok, ...over }).level, 'warn');
  }
});

test('signEnabled/broadcastEnabled: Core\'s exact conditions', () => {
  const base = { complete: false, hasWallet: true, privateKeysDisabled: false, couldSign: 1 };
  assert.equal(psbtlib.signEnabled(base), true);
  // psbtoperationsdialog.cpp:69 — every conjunct matters
  assert.equal(psbtlib.signEnabled({ ...base, complete: true }), false);
  assert.equal(psbtlib.signEnabled({ ...base, privateKeysDisabled: true }), false);
  assert.equal(psbtlib.signEnabled({ ...base, couldSign: 0 }), false);
  assert.equal(psbtlib.signEnabled({ ...base, hasWallet: false }), false);
  // :74 — broadcast is gated on completeness alone, so a watch-only wallet
  // can still broadcast a PSBT someone else finished
  assert.equal(psbtlib.broadcastEnabled(true), true);
  assert.equal(psbtlib.broadcastEnabled(false), false);
  assert.equal(psbtlib.psbtComplete({ next: 'finalizer' }), true);
  assert.equal(psbtlib.psbtComplete({ next: 'extractor' }), true);
  assert.equal(psbtlib.psbtComplete({ next: 'signer' }), false);
});

test('feeLine: a missing fee is "unable to calculate", not zero', () => {
  // analyzepsbt omits `fee` when an input amount is unknown — Core prints a
  // sentence there rather than showing a fee of 0, which would be a lie.
  assert.match(psbtlib.feeLine({ next: 'signer' }),
    /Unable to calculate transaction fee/);
  assert.match(psbtlib.feeLine({ fee: 0.0001 }), /Pays transaction fee/);
  // an explicit zero fee is a real value and must render as one
  assert.match(psbtlib.feeLine({ fee: 0 }), /Pays transaction fee/);
  assert.equal(psbtlib.psbtFee({ next: 'signer' }), null);
  assert.equal(psbtlib.psbtFee({ fee: 0 }), 0);
});

test('psbtOutputs / psbtInputAddresses / unsignedInputCount', () => {
  const outs = psbtlib.psbtOutputs(DECODED, { [PSBT_OUT_ADDR]: false, tb1qalpha: true });
  assert.equal(outs.length, 2);
  assert.equal(outs[0].address, PSBT_OUT_ADDR);
  assert.equal(outs[0].mine, false);
  assert.equal(outs[1].mine, true);         // change back to us
  // witness_utxo path
  assert.deepEqual(psbtlib.psbtInputAddresses(DECODED), [PSBT_IN_ADDR]);
  // non_witness_utxo path resolves through the spent vout index
  assert.deepEqual(psbtlib.psbtInputAddresses({
    tx: { vin: [{ vout: 1 }] },
    inputs: [{ non_witness_utxo: { vout: [
      { scriptPubKey: { address: 'wrong' } },
      { scriptPubKey: { address: 'right' } }] } }],
  }), ['right']);
  // an input we cannot resolve is null, never guessed
  assert.deepEqual(psbtlib.psbtInputAddresses({ tx: { vin: [{}] }, inputs: [{}] }), [null]);
  assert.equal(psbtlib.unsignedInputCount(ANALYSIS_NEEDS_SIG), 1);
  assert.equal(psbtlib.unsignedInputCount(ANALYSIS_COMPLETE), 0);
});

test('normalizePsbt: catches a paste that is not a PSBT before a round trip', () => {
  assert.deepEqual(psbtlib.normalizePsbt(`  ${PSBT_B64}\n`), { psbt: PSBT_B64 });
  assert.match(psbtlib.normalizePsbt('').error, /Paste a base64 PSBT/);
  // a raw hex transaction is the classic wrong paste
  assert.match(psbtlib.normalizePsbt('0200000001ab').error, /should start with "cHNidP"/);
});

test('bumpEligible: only our unconfirmed, replaceable, unabandoned sends', () => {
  const ok = {
    confirmations: 0,
    'bip125-replaceable': 'yes',
    details: [{ category: 'send', abandoned: false }],
  };
  assert.equal(psbtlib.bumpEligible(ok), true);
  assert.equal(psbtlib.bumpEligible({ ...ok, confirmations: 1 }), false);
  assert.equal(psbtlib.bumpEligible({ ...ok, 'bip125-replaceable': 'no' }), false);
  // "unknown" means the node could not decide — we must not offer it
  assert.equal(psbtlib.bumpEligible({ ...ok, 'bip125-replaceable': 'unknown' }), false);
  assert.equal(psbtlib.bumpEligible(
    { ...ok, details: [{ category: 'receive' }] }), false);
  assert.equal(psbtlib.bumpEligible(
    { ...ok, details: [{ category: 'send', abandoned: true }] }), false);
  // a watch-only wallet cannot sign the replacement, so it takes the PSBT path
  assert.equal(psbtlib.bumpMethod(false), 'bumpfee');
  assert.equal(psbtlib.bumpMethod(true), 'psbtbumpfee');
  assert.deepEqual(psbtlib.bumpParams('ab'), ['ab']);
  assert.deepEqual(psbtlib.bumpParams('ab', '12'), ['ab', { fee_rate: 12 }]);
});

test('PSBT tab: loads, decodes+analyzes on the wallet endpoint, renders Core\'s lines', async () => {
  rpcLog.length = 0;
  const card = await psbtTab(ANALYSIS_NEEDS_SIG);
  // Core's openWithPSBT fills first (fillPSBT sign=false), then analyses.
  const fill = rpcLog.find((c) => c.method === 'walletprocesspsbt');
  assert.equal(fill.params[1], false, 'the pre-analysis fill must not sign');
  for (const m of ['decodepsbt', 'analyzepsbt', 'finalizepsbt']) {
    assert.equal(rpcLog.find((c) => c.method === m).url, '/wallet/cold',
      `${m} must ride the wallet endpoint`);
  }
  assert.deepEqual(rpcLog.find((c) => c.method === 'decodepsbt').params, [PSBT_B64]);
  assert.match(card.textContent, /Transaction still needs signature\(s\)\./);
  assert.match(card.textContent, /Sends/);
  assert.match(card.textContent, /Pays transaction fee/);
  assert.match(card.textContent, /1 unsigned input\./);
  // change back to us is flagged, the recipient is not
  assert.match(card.textContent, /own address/);
  // signable => Sign offered, not yet complete => no broadcast
  assert.ok(buttonByText(card, 'sign'));
  assert.equal(buttonByText(card, 'broadcast'), null);
});

test('PSBT tab: a bad paste never reaches the node', async () => {
  fixtures.listwallets = () => ['cold', 'hot'];
  sessionStorage.setItem(wallet.WALLET_KEY, 'cold');
  wallet.resetWallet();
  await wallet.show(container, 'psbt');
  await wallet.refresh();
  byAria(container, 'Base64 PSBT').value = '0200000001deadbeef';
  rpcLog.length = 0;
  await byAria(container, 'PSBT').find((n) => n.tagName === 'FORM').dispatch('submit');
  assert.ok(!rpcLog.some((c) => c.method === 'decodepsbt'));
  assert.match(byAria(container, 'PSBT').textContent, /should start with "cHNidP"/);
});

test('PSBT tab: watch-only cannot sign, but can still broadcast a complete PSBT', async () => {
  // private keys disabled + already complete
  const card = await psbtTab(ANALYSIS_COMPLETE,
    { walletinfo: { ...WALLETINFO, private_keys_enabled: false } });
  assert.equal(buttonByText(card, 'sign'), null);
  assert.ok(buttonByText(card, 'broadcast'));
  assert.match(card.textContent, /fully signed and ready for broadcast/);
});

test('PSBT sign: goes through the unlock gate, then reloads the result', async () => {
  let locked = true;
  const card = await psbtTab(ANALYSIS_NEEDS_SIG, { walletinfo: ENC_INFO(0) });
  fixtures.getwalletinfo = () => ENC_INFO(locked ? 0 : Math.floor(Date.now() / 1000) + 300);
  fixtures.walletpassphrase = () => { locked = false; return null; };
  fixtures.walletlock = () => { locked = true; return null; };
  fixtures.walletprocesspsbt = (params) => (params[1]
    ? { psbt: PSBT_SIGNED, complete: true }      // the real signing call
    : { psbt: params[0], complete: false });     // the pre-analysis fill
  fixtures.analyzepsbt = () => ANALYSIS_COMPLETE;
  fixtures.finalizepsbt = () => ({ complete: true });
  rpcLog.length = 0;

  const signing = buttonByText(card, 'sign').dispatch('click');
  await tick();
  assert.ok(!rpcLog.some((c) => c.method === 'walletprocesspsbt'),
    'must not sign while the wallet is locked');
  byAria(container, 'Passphrase').value = 'hunter2';
  await byAria(container, 'Unlock wallet').dispatch('submit');
  await signing;

  const order = rpcLog.filter((c) =>
    c.method === 'walletpassphrase' || c.method === 'walletlock'
      || (c.method === 'walletprocesspsbt' && c.params[1] === true))
    .map((c) => c.method);
  assert.deepEqual(order, ['walletpassphrase', 'walletprocesspsbt', 'walletlock'],
    'unlock -> sign -> relock, like every other signing path');
  assert.deepEqual(
    rpcLog.find((c) => c.method === 'walletprocesspsbt' && c.params[1] === true).params,
    [PSBT_B64, true]);
  // the signed PSBT replaced the input and was re-analyzed
  assert.equal(byAria(container, 'Base64 PSBT').value, PSBT_SIGNED);
  assert.match(byAria(container, 'PSBT').textContent, /now complete/);
});

test('PSBT broadcast: finalize then sendrawtransaction, armed', async () => {
  const card = await psbtTab(ANALYSIS_COMPLETE);
  const txid = '9f'.repeat(32);
  fixtures.finalizepsbt = (params) => (params[1]
    ? { complete: true, hex: '0200dead' }   // extract=true: the broadcast path
    : { complete: true });                  // extract=false: the load probe
  fixtures.sendrawtransaction = () => txid;
  rpcLog.length = 0;
  const btn = buttonByText(card, 'broadcast');
  await btn.dispatch('click');                 // arms only
  assert.ok(!rpcLog.some((c) => c.method === 'sendrawtransaction'));
  await btn.dispatch('click');                 // acts
  assert.deepEqual(
    rpcLog.find((c) => c.method === 'finalizepsbt' && c.params[1] === true).params,
    [PSBT_B64, true]);
  // sendrawtransaction is a NODE method: base endpoint
  assert.equal(rpcLog.find((c) => c.method === 'sendrawtransaction').url, '/');
  assert.match(byAria(container, 'PSBT').textContent, /Transaction broadcast/);
});

test('PSBT broadcast refuses an incomplete finalize instead of sending', async () => {
  const card = await psbtTab(ANALYSIS_COMPLETE);
  // the load probe said complete, but the extracting finalize disagrees
  fixtures.finalizepsbt = (params) => (params[1] ? { complete: false } : { complete: true });
  rpcLog.length = 0;
  await confirmClick(buttonByText(card, 'broadcast'));
  assert.ok(!rpcLog.some((c) => c.method === 'sendrawtransaction'),
    'a finalize that did not complete must not be broadcast');
  assert.match(byAria(container, 'PSBT').textContent, /could not be finalized/);
});

test('fee bump: offered only on eligible rows, posts through the unlock gate', async () => {
  // The control lives in the expanded history row, which is where the
  // gettransaction fields the eligibility test needs already are.
  fixtures.listwallets = () => ['cold', 'hot'];
  sessionStorage.setItem(wallet.WALLET_KEY, 'cold');
  wallet.resetWallet();
  const BUMPABLE = 'b0'.repeat(32);
  fixtures.getwalletinfo = () => ENC_INFO(undefined);   // unencrypted: no prompt
  fixtures.listtransactions = () => ([{
    category: 'send', amount: -0.5, fee: -0.00001, address: RECIP_A, vout: 0,
    confirmations: 0, txid: BUMPABLE, time: NOW - 60, abandoned: false,
  }]);
  fixtures.gettransaction = () => ({
    amount: -0.5, fee: -0.00001, confirmations: 0, txid: BUMPABLE,
    walletconflicts: [], mempoolconflicts: [], time: NOW - 60,
    timereceived: NOW - 60, 'bip125-replaceable': 'yes',
    details: [{ category: 'send', amount: -0.5, abandoned: false }],
  });
  await wallet.show(container, 'history');
  await wallet.refresh();
  // expand the row to load its detail
  const row = byAria(container, 'Transaction history')
    .findAll((n) => n.tagName === 'TR').find((r) => r.textContent.includes('0.5'));
  await row.dispatch('click');
  await tick();

  const bump = byAria(container, `Bump fee for ${BUMPABLE}`);
  assert.ok(bump, 'an unconfirmed replaceable send must offer a bump');
  byAria(container, 'Bump fee rate (sat/vB)').value = '25';
  const REPLACEMENT = 'cc'.repeat(32);
  fixtures.psbtbumpfee = () => ({ psbt: PSBT_B64, origfee: 0.00001, fee: 0.00002, errors: [] });
  fixtures.bumpfee = () => ({ txid: REPLACEMENT, origfee: 0.00001, fee: 0.00002, errors: [] });
  rpcLog.length = 0;

  // Core never broadcasts a bump without showing the numbers: preview first,
  // built with psbtbumpfee, which does NOT broadcast.
  await buttonByText(bump, 'preview fee bump').dispatch('click');
  await tick();
  assert.ok(rpcLog.some((c) => c.method === 'psbtbumpfee'), 'preview must build it');
  assert.ok(!rpcLog.some((c) => c.method === 'bumpfee'),
    'previewing must not broadcast');
  const shown = byAria(container, `Bump fee for ${BUMPABLE}`).textContent;
  assert.match(shown, /current fee/);
  assert.match(shown, /new fee/);
  assert.match(shown, /increase/);
  assert.match(shown, /Nothing has been broadcast yet/);

  // only then can it be broadcast, and only behind the armed confirm
  rpcLog.length = 0;
  const go = buttonByText(byAria(container, `Bump fee for ${BUMPABLE}`),
    'broadcast replacement');
  await go.dispatch('click');                  // arms
  assert.ok(!rpcLog.some((c) => c.method === 'bumpfee'));
  await go.dispatch('click');                  // acts
  assert.deepEqual(rpcLog.find((c) => c.method === 'bumpfee'),
    { url: '/wallet/cold', method: 'bumpfee',
      params: [BUMPABLE, { fee_rate: 25 }] });
});

test('fee bump: a watch-only wallet previews and routes to the PSBT tab', async () => {
  // The method is decided at PREVIEW time, after refreshing walletinfo —
  // deciding it when the row was built would read a null walletinfo on a
  // direct load of History and hand a watch-only wallet `bumpfee`, which the
  // node refuses outright.
  fixtures.listwallets = () => ['cold', 'hot'];
  sessionStorage.setItem(wallet.WALLET_KEY, 'cold');
  wallet.resetWallet();
  const WO = 'd0'.repeat(32);
  fixtures.getwalletinfo = () => ({ ...WALLETINFO, private_keys_enabled: false });
  fixtures.listtransactions = () => ([{
    category: 'send', amount: -0.5, address: RECIP_A, vout: 0,
    confirmations: 0, txid: WO, time: NOW - 60, abandoned: false,
  }]);
  fixtures.gettransaction = () => ({
    amount: -0.5, confirmations: 0, txid: WO,
    walletconflicts: [], mempoolconflicts: [], time: NOW - 60,
    timereceived: NOW - 60, 'bip125-replaceable': 'yes',
    details: [{ category: 'send', amount: -0.5, abandoned: false }],
  });
  fixtures.psbtbumpfee = () => ({ psbt: PSBT_B64, origfee: 0.00001, fee: 0.00002, errors: [] });
  fixtures.decodepsbt = () => DECODED;
  fixtures.analyzepsbt = () => ANALYSIS_NEEDS_SIG;
  fixtures.walletprocesspsbt = (params) => ({ psbt: params[0], complete: false });
  fixtures.finalizepsbt = () => ({ complete: false });
  await wallet.show(container, 'history');
  await wallet.refresh();
  const row = byAria(container, 'Transaction history')
    .findAll((n) => n.tagName === 'TR').find((r) => r.textContent.includes('0.5'));
  await row.dispatch('click');
  await tick();
  rpcLog.length = 0;
  await buttonByText(byAria(container, `Bump fee for ${WO}`),
    'preview fee bump').dispatch('click');
  await tick();
  assert.ok(rpcLog.some((c) => c.method === 'psbtbumpfee'));
  assert.ok(!rpcLog.some((c) => c.method === 'bumpfee'),
    'a watch-only wallet must never be handed bumpfee');
  const bumpBox = byAria(container, `Bump fee for ${WO}`);
  assert.match(bumpBox.textContent, /cannot sign/);
  // and the replacement goes to the PSBT tab to be signed elsewhere
  await buttonByText(bumpBox, 'open in PSBT tab').dispatch('click');
  await tick();
  assert.equal(byAria(container, 'PSBT').hidden, false);
});

test('fee bump: a confirmed transaction offers no bump at all', async () => {
  fixtures.listwallets = () => ['cold', 'hot'];
  sessionStorage.setItem(wallet.WALLET_KEY, 'cold');
  wallet.resetWallet();
  const CONFIRMED = 'c0'.repeat(32);
  fixtures.getwalletinfo = () => ENC_INFO(undefined);
  fixtures.listtransactions = () => ([{
    category: 'send', amount: -0.25, address: RECIP_A, vout: 0,
    confirmations: 6, txid: CONFIRMED, time: NOW - 600, abandoned: false,
  }]);
  fixtures.gettransaction = () => ({
    amount: -0.25, confirmations: 6, txid: CONFIRMED,
    walletconflicts: [], mempoolconflicts: [], time: NOW - 600,
    timereceived: NOW - 600, 'bip125-replaceable': 'yes',
    details: [{ category: 'send', amount: -0.25, abandoned: false }],
  });
  await wallet.show(container, 'history');
  await wallet.refresh();
  const row = byAria(container, 'Transaction history')
    .findAll((n) => n.tagName === 'TR').find((r) => r.textContent.includes('0.25'));
  await row.dispatch('click');
  await tick();
  assert.equal(byAria(container, `Bump fee for ${CONFIRMED}`), null,
    'a confirmed transaction cannot be replaced');
});

test('PSBT: a partially-signed multisig is NOT reported as complete', async () => {
  // Our analyzepsbt calls an input `finalizer` as soon as it carries ANY
  // partial signature, unlike Core's role which means fully signed. Deriving
  // completeness from the role would tell a 2-of-2 co-signer their half-signed
  // PSBT is "fully signed and ready for broadcast", hide the Sign button
  // (signEnabled requires !complete), and then fail to broadcast — a dead end
  // on the most ordinary multi-party flow there is. finalizepsbt decides.
  const card = await psbtTab(
    { inputs: [{ has_utxo: true, is_final: false, next: 'finalizer' }],
      fee: 0.0001, next: 'finalizer' },
    { complete: false });                       // finalizepsbt disagrees
  assert.ok(buttonByText(card, 'sign'), 'the second signer must be able to sign');
  assert.equal(buttonByText(card, 'broadcast'), null,
    'an unfinalizable PSBT must not offer broadcast');
  assert.doesNotMatch(card.textContent, /fully signed and ready for broadcast/);
});

test('PSBT: an empty createpsbt handoff is filled before it is judged', async () => {
  // createpsbt emits no UTXO fields at all. Core fills the PSBT with our
  // UTXOs before analysing; without that the raw paste analyses as `updater`
  // ("missing information about inputs") with nothing signable — a dead end,
  // even though the node would fill and sign it on request.
  fixtures.listwallets = () => ['cold', 'hot'];
  fixtures.getwalletinfo = () => ENC_INFO(undefined);
  sessionStorage.setItem(wallet.WALLET_KEY, 'cold');
  wallet.resetWallet();
  // the fill turns the bare PSBT into one whose inputs we own
  fixtures.walletprocesspsbt = (params) => ({ psbt: `${params[0]}FILLED`, complete: false });
  fixtures.decodepsbt = (params) => (params[0].endsWith('FILLED')
    ? DECODED                                   // has witness_utxo now
    : { tx: DECODED.tx, inputs: [{}], outputs: [] });
  fixtures.analyzepsbt = (params) => (params[0].endsWith('FILLED')
    ? ANALYSIS_NEEDS_SIG
    : { inputs: [{ has_utxo: false, is_final: false, next: 'updater' }], next: 'updater' });
  fixtures.finalizepsbt = () => ({ complete: false });
  await wallet.show(container, 'psbt');
  await wallet.refresh();
  byAria(container, 'Base64 PSBT').value = PSBT_B64;
  await byAria(container, 'PSBT').find((n) => n.tagName === 'FORM').dispatch('submit');
  const card = byAria(container, 'PSBT');
  assert.doesNotMatch(card.textContent, /missing some information/);
  assert.ok(buttonByText(card, 'sign'), 'the filled PSBT is signable');
});

test('PSBT: clear then reload the same PSBT keeps the buttons', async () => {
  // The action row is stamped so the 3s poll cannot disarm the armed
  // broadcast confirm; clearing must reset that stamp, or reloading the SAME
  // PSBT matches it and the panel renders with no buttons at all.
  const card = await psbtTab(ANALYSIS_COMPLETE);
  assert.ok(buttonByText(card, 'broadcast'));
  await buttonByText(card, 'clear').dispatch('click');
  assert.equal(buttonByText(card, 'broadcast'), null);
  byAria(container, 'Base64 PSBT').value = PSBT_B64;
  await card.find((n) => n.tagName === 'FORM').dispatch('submit');
  assert.ok(buttonByText(byAria(container, 'PSBT'), 'broadcast'),
    'reloading the same PSBT must render its actions again');
});

test('PSBT: switching wallets drops the loaded PSBT', async () => {
  // state.psbt holds per-wallet derived data — couldSign, the own-address
  // flags, the sign/broadcast decision. Carrying it across a wallet switch
  // would offer Sign on a watch-only wallet and post to the wrong endpoint.
  await psbtTab(ANALYSIS_NEEDS_SIG);
  assert.ok(byAria(container, 'PSBT').textContent.includes('Sends'));
  const selector = byAria(container, 'Active wallet');
  selector.value = 'hot';
  await selector.dispatch('change');
  assert.doesNotMatch(byAria(container, 'PSBT').textContent, /Sends/);
});

test('fee bump: an already-bumped transaction offers no bump', async () => {
  // The original stays unconfirmed and replaceable-looking in the history,
  // so without the replaced_by_txid check the row keeps offering a bump the
  // node can only refuse.
  assert.equal(psbtlib.bumpEligible({
    confirmations: 0,
    'bip125-replaceable': 'yes',
    replaced_by_txid: 'ee'.repeat(32),
    details: [{ category: 'send', abandoned: false }],
  }), false);
});

test('countSignable: skips final inputs and unresolvable prevouts', () => {
  const infos = { mine: { ismine: true, solvable: true },
    theirs: { ismine: false, solvable: false } };
  const analysis = { inputs: [{ is_final: true }, { is_final: false }] };
  // input 0 is ours but already final -> nothing to add; input 1 is not ours
  assert.equal(psbtlib.countSignable(analysis, ['mine', 'theirs'], infos), 0);
  assert.equal(psbtlib.countSignable(
    { inputs: [{ is_final: false }] }, ['mine'], infos), 1);
  // an unresolvable prevout is never counted
  assert.equal(psbtlib.countSignable({ inputs: [{ is_final: false }] }, [null], infos), 0);
});

test('psbtStatus: an unfinalizable "finalizer" still reads as needing signatures', () => {
  const ok = { hasWallet: true, privateKeysDisabled: false, couldSign: 1 };
  // role alone (Core's meaning, and our node's when it is right)
  assert.match(psbtlib.psbtStatus({ next: 'finalizer' }, ok).text,
    /fully signed and ready for broadcast/);
  // ...but when finalizepsbt says otherwise, the role is not believed
  assert.match(psbtlib.psbtStatus({ next: 'finalizer' }, { ...ok, complete: false }).text,
    /still needs signature/);
  assert.match(psbtlib.psbtStatus({ next: 'extractor' }, { ...ok, complete: false }).text,
    /still needs signature/);
  // a confirmed-complete PSBT is unaffected
  assert.match(psbtlib.psbtStatus({ next: 'finalizer' }, { ...ok, complete: true }).text,
    /fully signed/);
});

// --- transport: 401 and 403 are different problems ------------------------

test('rpc: AuthError carries the status, so 403 is not reported as a bad password', async () => {
  // The Origin check rejects with 403 BEFORE auth (src/rpc/server.lisp:651).
  // Reporting that as "credentials rejected" sends the reader to re-check the
  // one thing that was already right — the credential.
  const realFetch = globalThis.fetch;
  try {
    for (const status of [401, 403]) {
      globalThis.fetch = async () => ({ status, ok: false, json: async () => ({}) });
      const e = await rpcmod.call('getblockcount').then(() => null, (err) => err);
      assert.ok(e instanceof rpcmod.AuthError, `${status} must be an AuthError`);
      assert.equal(e.status, status, 'the status must survive for the caller');
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});
