// GUI P3 peers-page tests (docs/gui-plan.md P3). Run from the repo root:
//
//   scripts/dev.sh ui-test
//
// Zero dependencies: a minimal DOM shim plus a stubbed global fetch drive
// the REAL ui/js modules — peers.js renders against fixture getpeerinfo/
// listbanned/getnetworkinfo responses, and every write action is asserted
// to POST the right JSON-RPC method with the right params through the real
// rpc.js helper. (The fiveam suite covers the Lisp side: asset serving,
// shell wiring, and the getpeerinfo fields these fixtures mirror.)

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
  // depth-first search helpers for assertions
  *walk() {
    yield this;
    for (const c of this.children) yield* c.walk();
  }
  find(pred) { for (const n of this.walk()) if (pred(n)) return n; return null; }
  findAll(pred) { return [...this.walk()].filter(pred); }
}

const byId = new Map();
globalThis.document = {
  createElement: (tag) => new Element(tag),
  getElementById: (id) => byId.get(id) ?? null,
};
byId.set('net-banner', new Element('div'));

globalThis.sessionStorage = {
  _m: new Map(),
  getItem(k) { return this._m.has(k) ? this._m.get(k) : null; },
  setItem(k, v) { this._m.set(k, String(v)); },
  removeItem(k) { this._m.delete(k); },
};

// --- stubbed JSON-RPC endpoint -------------------------------------------

// Fixtures mirror what src/rpc/net.lisp emits (a representative subset
// of the Core-parity field set): synced_blocks is always -1 (no
// last-common-block tracking), pingtime is ABSENT until a pong arrived, and
// the height column reads startingheight.
const NOW = Math.floor(Date.now() / 1000);
const PEER_FIXTURES = [
  { id: 0, addr: '203.0.113.7', version: 70016, subver: '/Satoshi:29.0.0/',
    services: '0000000000000c09', inbound: false, network: 'ipv4',
    transport_protocol_type: 'v2', connection_type: 'outbound-full-relay',
    relaytxes: true, startingheight: 905000, synced_headers: 905003,
    synced_blocks: -1, bytessent: 52340, bytesrecv: 1049000,
    addr_processed: 400, addr_rate_limited: 12, pingtime: 0.083 },
  { id: 1, addr: '2001:db8::beef', version: 70015, subver: '/miniclient:1.0/',
    services: '0000000000000009', inbound: true, network: 'ipv6',
    transport_protocol_type: 'v1', connection_type: 'inbound',
    relaytxes: true, startingheight: -1, synced_headers: -1,
    synced_blocks: -1, bytessent: 300, bytesrecv: 250,
    addr_processed: 0, addr_rate_limited: 0 },
  { id: 2, addr: 'expl0r6dbldpvzflmac2wtl3sad5f7tqoyfar2cyhcqnjbfaxxwbnzid.onion',
    version: 70016, subver: '/Satoshi:28.1.0/',
    services: '0000000000000c09', inbound: false, network: 'onion',
    transport_protocol_type: 'v1', connection_type: 'block-relay-only',
    relaytxes: false, startingheight: 905001, synced_headers: 905003,
    synced_blocks: -1, bytessent: 9000, bytesrecv: 4200000,
    addr_processed: 0, addr_rate_limited: 0, pingtime: 0.412 },
];
const fixtures = {
  getpeerinfo: () => PEER_FIXTURES,
  listbanned: () => [{ address: '198.51.100.66', banned_until: NOW + 86400 }],
  getnetworkinfo: () => ({ networkactive: true }),
  setban: () => null,
  disconnectnode: () => null,
  setnetworkactive: (params) => params[0],
};

const rpcLog = []; // every { method, params } POSTed through rpc.js

globalThis.fetch = async (url, opts) => {
  const payload = JSON.parse(opts.body);
  const requests = Array.isArray(payload) ? payload : [payload];
  const responses = requests.map((r) => {
    rpcLog.push({ method: r.method, params: r.params });
    const fn = fixtures[r.method];
    return fn
      ? { jsonrpc: '2.0', id: r.id, result: fn(r.params ?? []), error: null }
      : { jsonrpc: '2.0', id: r.id, result: null,
          error: { code: -32601, message: 'Method not found' } };
  });
  return {
    status: 200,
    ok: true,
    json: async () => (Array.isArray(payload) ? responses : responses[0]),
  };
};

// --- the real modules under test ------------------------------------------

const peers = await import('../../ui/js/peers.js');

// A two-step "armed" button: first click arms, second acts.
async function confirmClick(btn) {
  await btn.dispatch('click');
  await btn.dispatch('click');
}

function cellTexts(tr) { return tr.children.map((td) => td.textContent); }

function tableRows(container, cardIndex) {
  const card = container.children[cardIndex];
  const tbody = card.find((n) => n.tagName === 'TBODY');
  return tbody.children;
}

function headerButton(container, label) {
  return container.find((n) =>
    n.tagName === 'BUTTON' && n.dataset.key && n.textContent.startsWith(label));
}

const container = new Element('main');
await peers.show(container); // initial fetch + render with the fixtures

// --- pure helpers -----------------------------------------------------------

test('decodeServices names Core service bits and flags unknown ones', () => {
  assert.deepEqual(peers.decodeServices('0000000000000c09'),
    ['NETWORK', 'WITNESS', 'NETWORK_LIMITED', 'P2P_V2']);
  assert.deepEqual(peers.decodeServices('0000000000000429'),
    ['NETWORK', 'WITNESS', 'NETWORK_LIMITED', 'UNKNOWN[5]']);
  assert.deepEqual(peers.decodeServices('0000000000000000'), []);
});

test('peerNetwork classifies host-only address strings', () => {
  assert.equal(peers.peerNetwork('203.0.113.7'), 'ipv4');
  assert.equal(peers.peerNetwork('2001:db8::beef'), 'ipv6');
  assert.equal(peers.peerNetwork('abcdefexample.onion'), 'onion');
  assert.equal(peers.peerNetwork('example.b32.i2p'), 'i2p');
});

test('ban durations are the Qt peers-tab menu set', () => {
  assert.deepEqual(peers.BAN_DURATIONS.map((d) => d.seconds),
    [3600, 86400, 604800, 31536000]);
});

test('write-action params match the RPC signatures', () => {
  assert.deepEqual(peers.banParams('1.2.3.4', 3600),
    ['setban', ['1.2.3.4', 'add', 3600]]);
  assert.deepEqual(peers.unbanParams('1.2.3.4'), ['setban', ['1.2.3.4', 'remove']]);
  assert.deepEqual(peers.disconnectParams('1.2.3.4'), ['disconnectnode', ['1.2.3.4']]);
  assert.deepEqual(peers.setNetworkActiveParams(false), ['setnetworkactive', [false]]);
  assert.deepEqual(peers.setNetworkActiveParams(1), ['setnetworkactive', [true]]);
});

test('sortPeers: direction, unknown-last, id tie-break', () => {
  const ids = (rows) => rows.map((p) => p.id);
  assert.deepEqual(ids(peers.sortPeers(PEER_FIXTURES, 'ping', 1)), [0, 2, 1]);
  // unknown ping stays last even descending
  assert.deepEqual(ids(peers.sortPeers(PEER_FIXTURES, 'ping', -1)), [2, 0, 1]);
  assert.deepEqual(ids(peers.sortPeers(PEER_FIXTURES, 'recv', -1)), [2, 0, 1]);
  assert.deepEqual(ids(peers.sortPeers(PEER_FIXTURES, 'addr', 1)), [1, 0, 2]);
  // equal keys (transport v1 for ids 1 and 2) tie-break by id ascending
  assert.deepEqual(ids(peers.sortPeers(PEER_FIXTURES, 'transport', 1)), [1, 2, 0]);
});

// --- rendering from fixtures -------------------------------------------------

test('peer table renders one row per getpeerinfo entry, id-sorted', () => {
  const rows = tableRows(container, 1);
  assert.equal(rows.length, 3);
  const first = cellTexts(rows[0]);
  assert.equal(first[0], '0');
  assert.equal(first[1], '203.0.113.7');
  assert.equal(first[2], 'out');
  assert.equal(first[3], 'outbound-full-relay');
  assert.equal(first[4], 'v2');
  assert.equal(first[5], 'ipv4');
  assert.equal(first[6], '83 ms');
  assert.equal(first[7], '905,000'); // startingheight drives the height column
  assert.equal(first[10], '/Satoshi:29.0.0/');
  // unknown ping / pre-verack -1 height render as em dashes; ipv6 detected
  const second = cellTexts(rows[1]);
  assert.equal(second[4], 'v1');
  assert.equal(second[5], 'ipv6');
  assert.equal(second[6], '—');
  assert.equal(second[7], '—');
  // onion peer
  assert.equal(cellTexts(rows[2])[5], 'onion');
  const title = container.children[1].find((n) => n.tagName === 'H2');
  assert.equal(title.textContent, 'Peers (3)');
});

test('ban list renders listbanned with an unban action', () => {
  const rows = tableRows(container, 2);
  assert.equal(rows.length, 1);
  const cells = cellTexts(rows[0]);
  assert.equal(cells[0], '198.51.100.66');
  assert.ok(rows[0].find((n) => n.tagName === 'BUTTON' && n.textContent === 'unban'));
  const title = container.children[2].find((n) => n.tagName === 'H2');
  assert.equal(title.textContent, 'Banned addresses (1)');
});

test('network card shows active state; banner stays hidden', () => {
  assert.match(container.children[0].textContent, /networking is active/);
  assert.equal(byId.get('net-banner').hidden, true);
});

// --- sort behavior through header clicks -------------------------------------

test('clicking a header sorts; clicking again flips direction', async () => {
  const pingHeader = headerButton(container, 'ping');
  await pingHeader.dispatch('click');
  let rows = tableRows(container, 1);
  assert.deepEqual(rows.map((r) => cellTexts(r)[0]), ['0', '2', '1']);
  assert.match(pingHeader.textContent, /▲/);
  await pingHeader.dispatch('click');
  rows = tableRows(container, 1);
  assert.deepEqual(rows.map((r) => cellTexts(r)[0]), ['2', '0', '1']);
  assert.match(pingHeader.textContent, /▼/);
  // back to a deterministic id sort for the tests below
  const idHeader = headerButton(container, 'peer');
  await idHeader.dispatch('click');
});

// --- detail drawer -----------------------------------------------------------

test('row click opens the drawer with the full record', async () => {
  const rows = tableRows(container, 1);
  await rows[0].dispatch('click');
  const drawer = container.find((n) => n.tagName === 'ASIDE');
  assert.equal(drawer.hidden, false);
  const text = drawer.textContent;
  assert.match(text, /Peer 0/);
  assert.match(text, /203\.0\.113\.7/);
  assert.match(text, /outbound/);
  assert.match(text, /NETWORK, WITNESS, NETWORK_LIMITED, P2P_V2/);
  assert.match(text, /0000000000000c09/);
  assert.match(text, /83\.0 ms/);
  // the Wave-9 addr intake counters
  assert.match(text, /addresses processed400/);
  assert.match(text, /addresses rate-limited12/);
});

// --- write actions hit the right RPC with the right params -------------------

test('drawer disconnect: armed confirm, then disconnectnode(addr)', async () => {
  const drawer = container.find((n) => n.tagName === 'ASIDE');
  const btn = drawer.find((n) => n.tagName === 'BUTTON' && n.textContent === 'disconnect');
  rpcLog.length = 0;
  await btn.dispatch('click'); // arms only
  assert.equal(btn.textContent, 'confirm disconnect?');
  assert.ok(!rpcLog.some((c) => c.method === 'disconnectnode'));
  await btn.dispatch('click'); // acts
  assert.deepEqual(rpcLog.find((c) => c.method === 'disconnectnode'),
    { method: 'disconnectnode', params: ['203.0.113.7'] });
});

test('drawer ban: setban add with the chosen duration, no disconnect chase', async () => {
  const rows = tableRows(container, 1);
  await rows[2].dispatch('click'); // the onion peer, id 2
  const drawer = container.find((n) => n.tagName === 'ASIDE');
  const select = drawer.find((n) => n.tagName === 'SELECT');
  select.value = '604800'; // 1 week
  const btn = drawer.find((n) => n.tagName === 'BUTTON' && n.textContent === 'ban');
  rpcLog.length = 0;
  await confirmClick(btn);
  const calls = rpcLog.filter((c) => ['setban', 'disconnectnode'].includes(c.method));
  // setban itself disconnects the matching connected peer now (Core parity),
  // so the single RPC is the whole action.
  assert.deepEqual(calls, [
    { method: 'setban', params: [PEER_FIXTURES[2].addr, 'add', 604800] },
  ]);
});

test('unban: setban remove for the banned address', async () => {
  const rows = tableRows(container, 2);
  const btn = rows[0].find((n) => n.tagName === 'BUTTON');
  rpcLog.length = 0;
  await confirmClick(btn);
  assert.deepEqual(rpcLog.find((c) => c.method === 'setban'),
    { method: 'setban', params: ['198.51.100.66', 'remove'] });
});

test('ban form bans an arbitrary (unconnected) address — no disconnect', async () => {
  const form = container.children[2].find((n) => n.tagName === 'FORM');
  const input = form.find((n) => n.tagName === 'INPUT');
  const select = form.find((n) => n.tagName === 'SELECT');
  const btn = form.find((n) => n.tagName === 'BUTTON');
  input.value = ' 10.0.0.9 '; // trimmed by the handler
  select.value = '3600';
  rpcLog.length = 0;
  await confirmClick(btn);
  assert.deepEqual(rpcLog.find((c) => c.method === 'setban'),
    { method: 'setban', params: ['10.0.0.9', 'add', 3600] });
  assert.ok(!rpcLog.some((c) => c.method === 'disconnectnode'));
  assert.equal(input.value, '');
});

test('network toggle: setnetworkactive(false), banner + button flip', async () => {
  const netCard = container.children[0];
  let btn = netCard.find((n) =>
    n.tagName === 'BUTTON' && n.textContent === 'disable networking');
  assert.ok(btn);
  fixtures.getnetworkinfo = () => ({ networkactive: false });
  rpcLog.length = 0;
  await confirmClick(btn);
  assert.deepEqual(rpcLog.find((c) => c.method === 'setnetworkactive'),
    { method: 'setnetworkactive', params: [false] });
  // the post-action refresh saw networkactive:false
  assert.equal(byId.get('net-banner').hidden, false);
  assert.match(netCard.textContent, /DISABLED/);
  btn = netCard.find((n) =>
    n.tagName === 'BUTTON' && n.textContent === 'enable networking');
  assert.ok(btn, 're-enable affordance appears once disabled');
});

test('refresh() is a no-op while the view is hidden', async () => {
  container.hidden = true;
  rpcLog.length = 0;
  await peers.refresh();
  assert.equal(rpcLog.length, 0);
  container.hidden = false;
});
