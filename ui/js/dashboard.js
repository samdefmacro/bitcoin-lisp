// Node dashboard (gui-plan P1): one batched poll per tick feeds every card.

import * as rpc from './rpc.js';
import {
  fmtInt, fmtBytes, fmtRate, fmtDuration, fmtAge, fmtFeeRate, fmtPct, shortHash,
} from './format.js';

const $ = (id) => document.getElementById(id);

const RECENT_BLOCKS = 10;

// Client-side state carried between polls.
const state = {
  prev: null,          // { t, blocks, recv, sent } from the previous tick
  blockRate: null,     // EMA of blocks/sec, for the IBD ETA
  tipHash: null,       // last rendered tip, to skip recent-blocks refetches
  recentBlocks: [],    // [{ height, time, nTx, size, weight, hash }]
};

export function resetDashboard() {
  state.prev = null;
  state.blockRate = null;
  state.tipHash = null;
  state.recentBlocks = [];
}

function setText(id, text) { $(id).textContent = text; }

function normalizeWarnings(w) {
  if (!w) return [];
  if (typeof w === 'string') return w.trim() ? [w] : [];
  if (Array.isArray(w)) return w.filter((x) => typeof x === 'string' && x.trim());
  return [];
}

function renderSync(chain, now, headerHeight) {
  const blocks = chain.blocks ?? 0;
  // getchainstates reports the best-header height, which runs ahead of the
  // validated tip during sync; getblockchaininfo's headers trails it here.
  const headers = Math.max(chain.headers ?? 0, headerHeight ?? 0, blocks);
  const progress = chain.verificationprogress ?? 0;
  const ibd = !!chain.initialblockdownload;

  setText('sync-height', fmtInt(blocks));
  setText('sync-headers', fmtInt(headers));
  setText('sync-progress-label', fmtPct(progress));
  $('ibd-flag').hidden = !ibd;

  // Meter: verificationprogress when meaningful, else blocks/headers.
  const frac = progress > 0 ? progress : (headers > 0 ? blocks / headers : 0);
  const pctv = Math.min(100, Math.max(0, frac * 100));
  $('sync-meter-fill').style.width = `${pctv}%`;
  $('sync-meter').setAttribute('aria-valuenow', pctv.toFixed(1));

  setText('sync-hash', chain.bestblockhash || '—');
  setText('sync-age', chain.time ? `${fmtAge(chain.time, now)} ago` : '—');

  // Blocks/sec measured client-side across ticks (EMA), for a rough ETA.
  if (state.prev && blocks >= state.prev.blocks) {
    const dt = (now - state.prev.t) / 1000;
    if (dt > 0.5) {
      const inst = (blocks - state.prev.blocks) / dt;
      state.blockRate = state.blockRate === null
        ? inst
        : 0.7 * state.blockRate + 0.3 * inst;
    }
  } else {
    state.blockRate = null; // reorg/restart: measurement is meaningless
  }

  const remaining = headers - blocks;
  const showRate = ibd && state.blockRate !== null && state.blockRate > 0.001;
  $('sync-rate-row').hidden = !showRate;
  $('sync-eta-row').hidden = !(showRate && remaining > 0);
  if (showRate) {
    setText('sync-rate', state.blockRate.toFixed(state.blockRate < 10 ? 2 : 0));
    if (remaining > 0) setText('sync-eta', `~${fmtDuration(remaining / state.blockRate)}`);
  }
  return { blocks };
}

function renderPeers(net) {
  setText('peers-total', fmtInt(net.connections));
  setText('peers-in', fmtInt(net.connections_in));
  setText('peers-out', fmtInt(net.connections_out));
  setText('net-active', net.networkactive ? 'active' : 'disabled');
  // Global networking-disabled banner (gui-plan P3) — every view shows it;
  // the toggle itself lives on the peers page.
  $('net-banner').hidden = net.networkactive !== false;
}

function renderMempool(mem) {
  setText('mempool-count', fmtInt(mem.size));
  setText('mempool-bytes', fmtBytes(mem.bytes));
  setText('mempool-usage', fmtBytes(mem.usage));
  setText('mempool-minfee', fmtFeeRate(mem.mempoolminfee));
  setText('mempool-relayfee', fmtFeeRate(mem.minrelaytxfee));
  const unbroadcast = mem.unbroadcastcount;
  $('mempool-unbroadcast-row').hidden = !(unbroadcast > 0);
  if (unbroadcast > 0) setText('mempool-unbroadcast', fmtInt(unbroadcast));
}

function renderTraffic(tot, now) {
  setText('traffic-recv', fmtBytes(tot.totalbytesrecv));
  setText('traffic-sent', fmtBytes(tot.totalbytessent));
  let recvRate = '';
  let sentRate = '';
  if (state.prev) {
    const dt = (now - state.prev.t) / 1000;
    if (dt > 0.5) {
      recvRate = fmtRate(Math.max(0, tot.totalbytesrecv - state.prev.recv) / dt);
      sentRate = fmtRate(Math.max(0, tot.totalbytessent - state.prev.sent) / dt);
    }
  }
  setText('traffic-recv-rate', recvRate);
  setText('traffic-sent-rate', sentRate);
}

function renderNodeInfo(chain, net, uptime) {
  setText('chain-badge', chain?.chain ?? '—');
  if (net) {
    setText('node-subversion', net.subversion ?? '—');
    setText('node-version', `${net.subversion ?? ''} (protocol ${net.protocolversion ?? '?'})`);
  }
  setText('node-uptime', uptime === null ? '—' : fmtDuration(uptime));
}

function renderWarnings(...warningSets) {
  const all = [...new Set(warningSets.flatMap(normalizeWarnings))];
  const banner = $('warnings-banner');
  banner.hidden = all.length === 0;
  banner.textContent = all.join(' — ');
}

function renderRecentBlocks(now) {
  const body = $('blocks-body');
  if (state.recentBlocks.length === 0) {
    body.innerHTML = '<tr><td colspan="6" class="muted">no blocks</td></tr>';
    return;
  }
  body.replaceChildren(...state.recentBlocks.map((b) => {
    const tr = document.createElement('tr');
    const cells = [
      ['col-height', fmtInt(b.height)],
      ['col-age', b.time ? `${fmtAge(b.time, now)} ago` : '—'],
      ['col-ntx', fmtInt(b.nTx)],
      ['col-size', fmtBytes(b.size)],
      ['col-weight', fmtInt(b.weight)],
      ['col-hash', shortHash(b.hash)],
    ];
    for (const [cls, text] of cells) {
      const td = document.createElement('td');
      td.className = cls;
      td.textContent = text;
      if (cls === 'col-hash') td.title = b.hash;
      tr.appendChild(td);
    }
    return tr;
  }));
}

// Refetch the last N blocks; only called when the tip hash changed.
async function refreshRecentBlocks(chain) {
  const tip = chain.blocks ?? 0;
  const from = Math.max(0, tip - (RECENT_BLOCKS - 1));
  const heights = [];
  for (let h = tip; h >= from; h -= 1) heights.push(h);
  if (heights.length === 0 || !chain.bestblockhash) {
    state.recentBlocks = [];
    return;
  }
  const hashes = await rpc.batch(heights.map((h) => ['getblockhash', [h]]));
  const okHashes = hashes.filter((r) => !r.error && typeof r.result === 'string')
    .map((r) => r.result);
  const blocks = await rpc.batch(okHashes.map((h) => ['getblock', [h, 1]]));
  state.recentBlocks = blocks
    .filter((r) => !r.error && r.result)
    .map((r) => ({
      height: r.result.height,
      time: r.result.time,
      nTx: r.result.nTx,
      size: r.result.size,
      weight: r.result.weight,
      hash: r.result.hash,
    }));
}

// One poll tick. Throws on transport/auth failure (the scheduler handles
// the disconnected/re-auth states); per-method errors degrade single cards.
export async function tick() {
  const now = Date.now();
  const [chainR, netR, memR, totR, upR, statesR] = await rpc.batch([
    ['getblockchaininfo'],
    ['getnetworkinfo'],
    ['getmempoolinfo'],
    ['getnettotals'],
    ['uptime'],
    ['getchainstates'],
  ]);

  const chain = chainR.error ? null : chainR.result;
  const net = netR.error ? null : netR.result;
  const mem = memR.error ? null : memR.result;
  const tot = totR.error ? null : totR.result;
  const uptime = upR.error ? null : upR.result;
  const headerHeight = statesR.error ? null : statesR.result?.headers;

  renderNodeInfo(chain, net, uptime);
  renderWarnings(chain?.warnings, net?.warnings);
  if (net) renderPeers(net);
  if (mem) renderMempool(mem);
  if (tot) renderTraffic(tot, now);

  let blocks = state.prev?.blocks ?? 0;
  if (chain) {
    ({ blocks } = renderSync(chain, now, headerHeight));
    if (chain.bestblockhash && chain.bestblockhash !== state.tipHash) {
      await refreshRecentBlocks(chain);
      state.tipHash = chain.bestblockhash;
    }
  }
  renderRecentBlocks(now);

  state.prev = {
    t: now,
    blocks,
    recv: tot?.totalbytesrecv ?? state.prev?.recv ?? 0,
    sent: tot?.totalbytessent ?? state.prev?.sent ?? 0,
  };
  setText('last-poll', new Date(now).toLocaleTimeString());
}
