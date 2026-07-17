// Peers & network ops (gui-plan P3): sortable peer table + detail drawer,
// ban management, network-active toggle — Qt's Peers tab transposed.
//
// RPC shapes consumed here are exactly what src/rpc/methods.lisp emits:
//
//   getpeerinfo -> [{ id, addr, version, subver, services (16-hex string),
//     inbound, transport_protocol_type ("v1"|"v2"), connection_type,
//     relaytxes, startingheight, synced_headers, synced_blocks, bytessent,
//     bytesrecv, addr_processed, addr_rate_limited,
//     pingtime (seconds, 0 = unknown) }].
//     addr is the host only (no port) — it is exactly the string
//     disconnectnode matches and the ban list keys on.
//   listbanned -> [{ address, banned_until (unix) }] — no ban_created/
//     ban_duration/time_remaining fields (unlike Core).
//   setban [address, "add", seconds] / [address, "remove"]; addresses are
//     matched exactly (no subnet/CIDR support). Our setban does NOT drop a
//     connected peer (Core's does), so banAddress chains a disconnectnode
//     for any connected peer with that address.
//   disconnectnode [address] -> null, error -1 when not connected.
//   setnetworkactive [bool] -> the new state; disabling drops every peer.
//
// The pure helpers up top (sorting, cell shaping, param builders, service
// decoding) are exported for the node test harness (tests/ui/peers.test.mjs).

import * as rpc from './rpc.js';
import { fmtInt, fmtBytes, fmtDuration, fmtTimestamp } from './format.js';

// --- pure helpers (exported for tests) --------------------------------

// Qt's Peers-tab ban menu durations (rpcconsole.cpp banSelectedNode).
export const BAN_DURATIONS = [
  { label: '1 hour', seconds: 60 * 60 },
  { label: '24 hours', seconds: 60 * 60 * 24 },
  { label: '1 week', seconds: 60 * 60 * 24 * 7 },
  { label: '1 year', seconds: 60 * 60 * 24 * 365 },
];

// Service-flag names by bit, per Core ServiceFlagsToStr (protocol.cpp).
const SERVICE_BITS = [
  [0, 'NETWORK'], [1, 'GETUTXO'], [2, 'BLOOM'], [3, 'WITNESS'],
  [6, 'COMPACT_FILTERS'], [10, 'NETWORK_LIMITED'], [11, 'P2P_V2'],
];

// Decode getpeerinfo's 16-hex-digit services string to flag names,
// with UNKNOWN[bit] for bits Core has no name for.
export function decodeServices(hex) {
  const bits = BigInt(`0x${hex || '0'}`);
  const names = [];
  for (const [bit, name] of SERVICE_BITS) {
    if (bits & (1n << BigInt(bit))) names.push(name);
  }
  for (let bit = 0n; bit < 64n; bit += 1n) {
    if ((bits & (1n << bit)) && !SERVICE_BITS.some(([b]) => BigInt(b) === bit)) {
      names.push(`UNKNOWN[${bit}]`);
    }
  }
  return names;
}

// Which network an address string belongs to (addr is host-only, so a
// colon can only be IPv6). Display-only, like Qt's Network column.
export function peerNetwork(addr) {
  const a = (addr || '').toLowerCase();
  if (a.endsWith('.onion')) return 'onion';
  if (a.endsWith('.i2p')) return 'i2p';
  if (a.includes(':')) return 'ipv6';
  return a ? 'ipv4' : '—';
}

// Sortable peer-table columns. `value` extracts the sort key (string or
// number; null/undefined sorts last in either direction); `cell` the
// display text.
export const COLUMNS = [
  { key: 'id', label: 'peer', numeric: true,
    value: (p) => p.id, cell: (p) => fmtInt(p.id) },
  { key: 'addr', label: 'address',
    value: (p) => p.addr || '', cell: (p) => p.addr || '—' },
  { key: 'direction', label: 'dir',
    value: (p) => (p.inbound ? 'in' : 'out'),
    cell: (p) => (p.inbound ? 'in' : 'out') },
  { key: 'type', label: 'type',
    value: (p) => p.connection_type || '',
    cell: (p) => p.connection_type || '—' },
  { key: 'transport', label: 'transport',
    value: (p) => p.transport_protocol_type || 'v1',
    cell: (p) => p.transport_protocol_type || 'v1' },
  { key: 'network', label: 'net',
    value: (p) => peerNetwork(p.addr), cell: (p) => peerNetwork(p.addr) },
  { key: 'ping', label: 'ping', numeric: true,
    value: (p) => (p.pingtime > 0 ? p.pingtime : null),
    cell: (p) => (p.pingtime > 0 ? `${(p.pingtime * 1000).toFixed(0)} ms` : '—') },
  { key: 'height', label: 'height', numeric: true,
    value: (p) => (p.synced_blocks >= 0 ? p.synced_blocks : null),
    cell: (p) => (p.synced_blocks >= 0 ? fmtInt(p.synced_blocks) : '—') },
  { key: 'sent', label: 'sent', numeric: true,
    value: (p) => p.bytessent ?? 0, cell: (p) => fmtBytes(p.bytessent) },
  { key: 'recv', label: 'recv', numeric: true,
    value: (p) => p.bytesrecv ?? 0, cell: (p) => fmtBytes(p.bytesrecv) },
  { key: 'subver', label: 'user agent',
    value: (p) => p.subver || '', cell: (p) => p.subver || '—' },
];

// Sort PEERS by the column named KEY, DIR = 1 (asc) | -1 (desc). Unknown
// values (null) sort last regardless of direction; ties break by id asc.
export function sortPeers(peers, key, dir) {
  const col = COLUMNS.find((c) => c.key === key) || COLUMNS[0];
  return [...peers].sort((a, b) => {
    const va = col.value(a);
    const vb = col.value(b);
    if (va === null || va === undefined) {
      return (vb === null || vb === undefined) ? a.id - b.id : 1;
    }
    if (vb === null || vb === undefined) return -1;
    let cmp;
    if (typeof va === 'string') cmp = va < vb ? -1 : (va > vb ? 1 : 0);
    else cmp = va - vb;
    return cmp !== 0 ? cmp * dir : a.id - b.id;
  });
}

// [method, params] pairs for every write action, kept as one testable seam.
export function banParams(address, seconds) {
  return ['setban', [address, 'add', seconds]];
}
export function unbanParams(address) {
  return ['setban', [address, 'remove']];
}
export function disconnectParams(address) {
  return ['disconnectnode', [address]];
}
export function setNetworkActiveParams(active) {
  return ['setnetworkactive', [!!active]];
}

// --- module state ------------------------------------------------------

const state = {
  container: null,   // the #view-peers main, once show() has built it
  refs: null,        // named DOM nodes inside the skeleton
  sortKey: 'id',
  sortDir: 1,
  selectedId: null,  // peer id open in the drawer, or null
  peers: [],
  banned: [],
  networkActive: null,
  refreshing: false,
};

// --- DOM helpers (textContent only for dynamic data — no injection) ---

function el(tag, className = '', text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function kvRow(label, ...values) {
  const row = el('div');
  row.appendChild(el('dt', '', label));
  const dd = el('dd', 'mono');
  dd.append(...values);
  row.appendChild(dd);
  return row;
}

function rpcErrorMessage(e) {
  if (e instanceof rpc.RpcError) return `${e.message} (RPC error ${e.code})`;
  if (e instanceof rpc.AuthError) return `Session ended: ${e.message}`;
  return `Could not reach the node: ${e.message}`;
}

// A destructive-action button that arms on the first click ("confirm …?")
// and only acts on the second, disarming itself after 4s. RUN may throw;
// the caller surfaces the error.
function armedButton(label, confirmLabel, run, className = 'btn btn-danger') {
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

// Run an action, routing failure text into ERREL, then refresh all data.
async function runAction(errEl, fn) {
  errEl.hidden = true;
  try {
    await fn();
  } catch (e) {
    errEl.textContent = rpcErrorMessage(e);
    errEl.hidden = false;
  }
  await refresh();
}

// --- write actions ------------------------------------------------------

// Ban ADDRESS, then disconnect any connected peer with that exact address
// (Core's setban disconnects matching peers itself; ours does not).
async function banAddress(address, seconds) {
  await rpc.call(...banParams(address, seconds));
  if (state.peers.some((p) => p.addr === address)) {
    try {
      await rpc.call(...disconnectParams(address));
    } catch { /* raced a disconnect — the ban itself succeeded */ }
  }
}

// --- skeleton -----------------------------------------------------------

// Build the static structure once per login/container; refresh() fills it.
// Returns the initial refresh's promise (awaited by tests, not by app.js).
export function show(container) {
  if (state.container !== container || !state.refs) {
    state.container = container;
    state.selectedId = null;
    buildSkeleton(container);
  }
  return refresh();
}

export function resetPeers() {
  state.container = null;
  state.refs = null;
  state.selectedId = null;
  state.peers = [];
  state.banned = [];
  state.networkActive = null;
}

function buildSkeleton(container) {
  const refs = {};

  // Network card: active/disabled state + the setnetworkactive toggle.
  const netCard = el('section', 'card card-full');
  netCard.setAttribute('aria-label', 'Network activity');
  netCard.appendChild(el('h2', 'card-title', 'Network'));
  const netLine = el('div', 'net-line');
  refs.netStatus = el('span', 'net-status', '—');
  refs.netToggleHolder = el('span');
  netLine.append(refs.netStatus, refs.netToggleHolder);
  netCard.appendChild(netLine);
  netCard.appendChild(el('p', 'muted net-hint',
    'Disabling drops every peer and stops all connections until re-enabled.'));
  refs.netError = el('p', 'error-text');
  refs.netError.hidden = true;
  netCard.appendChild(refs.netError);

  // Peers card: sortable table; a row click opens the detail drawer.
  const peersCard = el('section', 'card card-full');
  peersCard.setAttribute('aria-label', 'Connected peers');
  refs.peersTitle = el('h2', 'card-title', 'Peers');
  peersCard.appendChild(refs.peersTitle);
  const wrap = el('div', 'table-wrap');
  const table = el('table', 'peers');
  const thead = el('thead');
  const hrow = el('tr');
  for (const col of COLUMNS) {
    const th = el('th', col.numeric ? 'num' : '');
    const btn = el('button', 'th-sort', col.label);
    btn.type = 'button';
    btn.dataset.key = col.key;
    btn.addEventListener('click', () => {
      if (state.sortKey === col.key) state.sortDir = -state.sortDir;
      else { state.sortKey = col.key; state.sortDir = 1; }
      renderPeerTable();
    });
    th.appendChild(btn);
    hrow.appendChild(th);
  }
  thead.appendChild(hrow);
  refs.peersHead = hrow;
  refs.peersBody = el('tbody');
  table.append(thead, refs.peersBody);
  wrap.appendChild(table);
  peersCard.appendChild(wrap);
  refs.peersError = el('p', 'error-text');
  refs.peersError.hidden = true;
  peersCard.appendChild(refs.peersError);

  // Ban card: manual-ban form + the listbanned table with unban actions.
  const banCard = el('section', 'card card-full');
  banCard.setAttribute('aria-label', 'Banned addresses');
  refs.banTitle = el('h2', 'card-title', 'Banned addresses');
  banCard.appendChild(refs.banTitle);

  const form = el('form', 'ban-form');
  refs.banInput = el('input');
  refs.banInput.placeholder = 'address to ban (exact match)';
  refs.banInput.spellcheck = false;
  refs.banInput.setAttribute('aria-label', 'Address to ban');
  refs.banSelect = el('select');
  refs.banSelect.setAttribute('aria-label', 'Ban duration');
  for (const d of BAN_DURATIONS) {
    const opt = el('option', '', `ban for ${d.label}`);
    opt.value = String(d.seconds);
    refs.banSelect.appendChild(opt);
  }
  refs.banSelect.value = String(BAN_DURATIONS[1].seconds); // 24h, setban's default
  refs.banError = el('p', 'error-text');
  refs.banError.hidden = true;
  const banBtn = armedButton('ban', 'confirm ban?', async () => {
    const address = refs.banInput.value.trim();
    if (!address) return;
    await runAction(refs.banError, async () => {
      await banAddress(address, parseInt(refs.banSelect.value, 10));
      refs.banInput.value = '';
    });
  });
  form.addEventListener('submit', (ev) => ev.preventDefault());
  form.append(refs.banInput, refs.banSelect, banBtn);
  banCard.append(form, refs.banError); // ban/unban action errors land here

  const banWrap = el('div', 'table-wrap');
  const banTable = el('table', 'peers banlist');
  const banHead = el('thead');
  const banHrow = el('tr');
  for (const label of ['address', 'banned until', 'remaining', '']) {
    banHrow.appendChild(el('th', '', label));
  }
  banHead.appendChild(banHrow);
  refs.banBody = el('tbody');
  banTable.append(banHead, refs.banBody);
  banWrap.appendChild(banTable);
  refs.banFetchError = el('p', 'error-text'); // listbanned poll failures
  refs.banFetchError.hidden = true;
  banCard.append(banWrap, refs.banFetchError);

  // Detail drawer (hidden until a row is selected).
  refs.drawer = el('aside', 'drawer');
  refs.drawer.hidden = true;
  refs.drawer.setAttribute('aria-label', 'Peer details');
  const dhead = el('div', 'drawer-head');
  refs.drawerTitle = el('h2', 'card-title', 'Peer');
  const close = el('button', 'linklike', 'close');
  close.type = 'button';
  close.addEventListener('click', closeDrawer);
  dhead.append(refs.drawerTitle, close);
  refs.drawerData = el('div');
  refs.drawerActions = el('div', 'drawer-actions');
  refs.drawerError = el('p', 'error-text');
  refs.drawerError.hidden = true;
  refs.drawer.append(dhead, refs.drawerData, refs.drawerActions, refs.drawerError);
  refs.drawer.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') closeDrawer();
  });

  state.refs = refs;
  container.replaceChildren(netCard, peersCard, banCard, refs.drawer);
}

// --- refresh: one batched fetch feeds every region ----------------------

// Re-fetch and re-render. No-ops when the peers view is not on screen, so
// app.js can call it from the shared 3s poll unconditionally.
export async function refresh() {
  const { container, refs } = state;
  if (!container || container.hidden || !refs || state.refreshing) return;
  state.refreshing = true;
  try {
    const [peersR, bannedR, netR] = await rpc.batch([
      ['getpeerinfo'], ['listbanned'], ['getnetworkinfo'],
    ]);
    refs.peersError.hidden = !peersR.error;
    if (peersR.error) refs.peersError.textContent = peersR.error.message;
    else state.peers = peersR.result || [];
    refs.banFetchError.hidden = !bannedR.error;
    if (bannedR.error) refs.banFetchError.textContent = bannedR.error.message;
    else state.banned = bannedR.result || [];
    if (!netR.error && netR.result) {
      state.networkActive = !!netR.result.networkactive;
    }
    renderNetwork();
    renderPeerTable();
    renderBanTable();
    renderDrawerData();
  } finally {
    state.refreshing = false;
  }
}

function renderNetwork() {
  const { refs, networkActive } = state;
  if (networkActive === null) return;
  refs.netStatus.textContent = networkActive
    ? 'P2P networking is active.'
    : 'P2P networking is DISABLED — no peer connections are made or accepted.';
  refs.netStatus.className = `net-status ${networkActive ? '' : 'net-off'}`;
  // Rebuild the toggle only when the state it acts on changed, so an armed
  // confirm is never reset by the background poll.
  if (refs.netToggleFor !== networkActive) {
    refs.netToggleFor = networkActive;
    const btn = networkActive
      ? armedButton('disable networking', 'confirm disable?', () =>
          runAction(refs.netError, () =>
            rpc.call(...setNetworkActiveParams(false))))
      : armedButton('enable networking', 'confirm enable?', () =>
          runAction(refs.netError, () =>
            rpc.call(...setNetworkActiveParams(true))), 'btn');
    refs.netToggleHolder.replaceChildren(btn);
  }
  // Global banner, visible on every view (dashboard.js keeps it fresh too).
  const banner = document.getElementById('net-banner');
  if (banner) banner.hidden = networkActive;
}

function renderPeerTable() {
  const { refs } = state;
  refs.peersTitle.textContent = `Peers (${fmtInt(state.peers.length)})`;
  // aria-sort + indicator on the active header
  for (const th of refs.peersHead.children) {
    const btn = th.firstChild;
    const active = btn.dataset.key === state.sortKey;
    th.setAttribute('aria-sort',
      active ? (state.sortDir === 1 ? 'ascending' : 'descending') : 'none');
    btn.classList.toggle('sorted', active);
    const col = COLUMNS.find((c) => c.key === btn.dataset.key);
    btn.textContent = active
      ? `${col.label} ${state.sortDir === 1 ? '▲' : '▼'}`
      : col.label;
  }
  if (state.peers.length === 0) {
    const tr = el('tr');
    const td = el('td', 'muted', state.networkActive === false
      ? 'no peers — networking is disabled'
      : 'no peers connected');
    td.colSpan = COLUMNS.length;
    tr.appendChild(td);
    refs.peersBody.replaceChildren(tr);
    return;
  }
  const sorted = sortPeers(state.peers, state.sortKey, state.sortDir);
  refs.peersBody.replaceChildren(...sorted.map((p) => {
    const tr = el('tr', p.id === state.selectedId ? 'selected' : '');
    tr.tabIndex = 0;
    tr.setAttribute('role', 'button');
    tr.setAttribute('aria-label', `Peer ${p.id} details`);
    const open = () => openDrawer(p.id);
    tr.addEventListener('click', open);
    tr.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); }
    });
    for (const col of COLUMNS) {
      const td = el('td', col.numeric ? 'num' : '', col.cell(p));
      if (col.key === 'subver') td.classList.add('col-subver');
      tr.appendChild(td);
    }
    return tr;
  }));
}

function renderBanTable() {
  const { refs } = state;
  refs.banTitle.textContent = `Banned addresses (${fmtInt(state.banned.length)})`;
  // Skip the rebuild when nothing changed, so the poll never swaps out an
  // armed unban confirm mid-click ("remaining" only re-renders on changes,
  // which is fine at its h/m/s granularity).
  const stamp = JSON.stringify(state.banned);
  if (refs.banStamp === stamp) return;
  refs.banStamp = stamp;
  if (state.banned.length === 0) {
    const tr = el('tr');
    const td = el('td', 'muted', 'no banned addresses');
    td.colSpan = 4;
    tr.appendChild(td);
    refs.banBody.replaceChildren(tr);
    return;
  }
  const nowSecs = Date.now() / 1000;
  const rows = [...state.banned]
    .sort((a, b) => (a.address < b.address ? -1 : 1))
    .map((ban) => {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', ban.address));
      tr.appendChild(el('td', 'mono', fmtTimestamp(ban.banned_until)));
      tr.appendChild(el('td', 'mono muted',
        ban.banned_until > nowSecs ? fmtDuration(ban.banned_until - nowSecs) : '—'));
      const td = el('td', 'num');
      td.appendChild(armedButton('unban', 'confirm unban?', () =>
        runAction(refs.banError, () =>
          rpc.call(...unbanParams(ban.address))), 'btn'));
      tr.appendChild(td);
      return tr;
    });
  refs.banBody.replaceChildren(...rows);
}

// --- detail drawer ------------------------------------------------------

function openDrawer(peerId) {
  state.selectedId = peerId;
  state.refs.drawer.hidden = false; // before the render, which no-ops when hidden
  buildDrawerActions();
  renderDrawerData();
  renderPeerTable(); // row highlight
}

function closeDrawer() {
  state.selectedId = null;
  state.refs.drawer.hidden = true;
  renderPeerTable();
}

// Actions are (re)built when the drawer opens — never on the poll — so an
// armed confirm can't be swapped out from under the pointer.
function buildDrawerActions() {
  const { refs } = state;
  const peer = state.peers.find((p) => p.id === state.selectedId);
  refs.drawerError.hidden = true;
  if (!peer) {
    refs.drawerActions.replaceChildren();
    return;
  }
  const { addr } = peer;
  const banSelect = el('select');
  banSelect.setAttribute('aria-label', 'Ban duration');
  for (const d of BAN_DURATIONS) {
    const opt = el('option', '', d.label);
    opt.value = String(d.seconds);
    banSelect.appendChild(opt);
  }
  banSelect.value = String(BAN_DURATIONS[1].seconds);
  refs.drawerActions.replaceChildren(
    armedButton('disconnect', 'confirm disconnect?', () =>
      runAction(refs.drawerError, () =>
        rpc.call(...disconnectParams(addr)))),
    banSelect,
    armedButton('ban', 'confirm ban?', () =>
      runAction(refs.drawerError, () =>
        banAddress(addr, parseInt(banSelect.value, 10)))),
  );
}

// The full getpeerinfo record, refreshed on every poll while open.
function renderDrawerData() {
  const { refs, selectedId } = state;
  if (selectedId === null || refs.drawer.hidden) return;
  const peer = state.peers.find((p) => p.id === selectedId);
  refs.drawerTitle.textContent = `Peer ${selectedId}`;
  if (!peer) {
    refs.drawerData.replaceChildren(
      el('p', 'muted', 'This peer is no longer connected.'));
    refs.drawerActions.replaceChildren();
    return;
  }
  const services = decodeServices(peer.services);
  const kv = el('dl', 'kv');
  const rows = [
    ['address', peer.addr || '—'],
    ['direction', peer.inbound ? 'inbound' : 'outbound'],
    ['connection type', peer.connection_type || '—'],
    ['transport', peer.transport_protocol_type || 'v1'],
    ['network', peerNetwork(peer.addr)],
    ['version', `${peer.version ?? '—'}`],
    ['user agent', peer.subver || '—'],
    ['services', services.length ? services.join(', ') : 'none'],
    ['services (hex)', peer.services || '—'],
    ['relays txs', peer.relaytxes ? 'yes' : 'no'],
    ['starting height', peer.startingheight >= 0 ? fmtInt(peer.startingheight) : '—'],
    ['synced headers', peer.synced_headers >= 0 ? fmtInt(peer.synced_headers) : '—'],
    ['synced blocks', peer.synced_blocks >= 0 ? fmtInt(peer.synced_blocks) : '—'],
    ['ping', peer.pingtime > 0 ? `${(peer.pingtime * 1000).toFixed(1)} ms` : 'unknown'],
    ['bytes sent', `${fmtBytes(peer.bytessent)} (${fmtInt(peer.bytessent)} B)`],
    ['bytes received', `${fmtBytes(peer.bytesrecv)} (${fmtInt(peer.bytesrecv)} B)`],
    ['addresses processed', fmtInt(peer.addr_processed)],
    ['addresses rate-limited', fmtInt(peer.addr_rate_limited)],
  ];
  const known = new Set(['id', 'addr', 'inbound', 'connection_type',
    'transport_protocol_type', 'version', 'subver', 'services', 'relaytxes',
    'startingheight', 'synced_headers', 'synced_blocks', 'pingtime',
    'bytessent', 'bytesrecv', 'addr_processed', 'addr_rate_limited']);
  // Any field this UI predates still shows up, raw.
  for (const [k, v] of Object.entries(peer)) {
    if (!known.has(k)) rows.push([k, typeof v === 'object' ? JSON.stringify(v) : `${v}`]);
  }
  for (const [label, text] of rows) kv.appendChild(kvRow(label, `${text}`));
  refs.drawerData.replaceChildren(kv);
}
