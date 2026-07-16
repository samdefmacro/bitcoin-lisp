// Block/tx explorer + universal search (gui-plan P2).
//
// RPC shapes consumed here are exactly what src/rpc/methods.lisp emits:
//
//   getblockhash <height>  -> hash hex (error -8 when out of range)
//   getblock <hash> 1      -> { hash, confirmations, height, versionHex,
//     mediantime, bits, target, difficulty, chainwork, nextblockhash?,
//     strippedsize, size, weight, version, merkleroot, time, nonce, nTx,
//     previousblockhash, tx: [txid…] }. The chain-context fields
//     (confirmations/height/…/nextblockhash) are absent when the block is not
//     in the index; confirmations is -1 for a block off the active chain.
//     Verbosity 2 adds full tx objects but NO prevout data (our node folds
//     Core's verbosity 3 into 2), so the tx list uses verbosity 1.
//   getrawtransaction <txid> 1 -> { txid, hash(wtxid), version, size, vsize,
//     weight, locktime, vin, vout, hex } — plus blockhash (+ confirmations/
//     time/blocktime on the active chain, or confirmations:0 for a stale
//     block) only when found via txindex or a blockhash hint; a mempool hit
//     carries no block fields at all. Core's verbosity-2 fee/prevout fields
//     are NOT emitted, so prevouts are resolved client-side with one
//     getrawtransaction per distinct funding txid (which needs the funding tx
//     to be in the mempool or reachable through txindex; unresolvable inputs
//     degrade to "unavailable" and the fee is not shown).

import * as rpc from './rpc.js';
import { navigate, replaceHash } from './router.js';
import {
  fmtInt, fmtBytes, fmtAge, fmtBtc, fmtSats, fmtTimestamp, fmtDifficulty,
  shortHash, shortId,
} from './format.js';

const TXS_PER_PAGE = 25;      // block-page tx list page size
const PREVOUT_BATCH = 25;     // getrawtransaction calls per HTTP round trip
const MAX_PREVOUT_TXS = 200;  // stop resolving prevouts beyond this many funding txs
const IO_CHUNK = 100;         // inputs/outputs rendered per "show more" click
const ZERO_HASH = '0'.repeat(64);
const SEQUENCE_FINAL = 0xffffffff;
const HASH64 = /^[0-9a-fA-F]{64}$/;

// Bumped on every navigation; in-flight async renders check it before
// touching the DOM so a stale fetch never clobbers the current page.
let epoch = 0;

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

async function copyToClipboard(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = 'copied';
  } catch {
    btn.textContent = 'copy failed';
  }
  setTimeout(() => { btn.textContent = 'copy'; }, 1200);
}

// Value (possibly truncated for display) with a copy-the-full-value button.
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

function pill(text, variant = '') {
  return el('span', `pill ${variant}`, text);
}

function kvRow(label, ...values) {
  const row = el('div');
  row.appendChild(el('dt', '', label));
  const dd = el('dd', 'mono');
  dd.append(...values);
  row.appendChild(dd);
  return row;
}

function card(title) {
  const section = el('section', 'card card-full');
  section.appendChild(el('h2', 'card-title', title));
  return section;
}

function renderNotice(container, title, className, text) {
  const c = card(title);
  c.appendChild(el('p', className, text));
  container.replaceChildren(c);
}

function renderError(container, title, message) {
  renderNotice(container, title, 'error-text', message);
}

function renderLoading(container, title) {
  renderNotice(container, title, 'muted', 'loading…');
}

function rpcErrorMessage(e) {
  if (e instanceof rpc.RpcError) return `${e.message} (RPC error ${e.code})`;
  if (e instanceof rpc.AuthError) return `Session ended: ${e.message}`;
  return `Could not reach the node: ${e.message}`;
}

// A <details> reveal holding labeled <pre> hex/asm blocks.
function reveal(summaryText, blocks) {
  const d = el('details', 'reveal');
  d.appendChild(el('summary', '', summaryText));
  for (const [label, text] of blocks) {
    if (!text) continue;
    d.appendChild(el('div', 'reveal-label', label));
    d.appendChild(el('pre', '', text));
  }
  return d;
}

// Sum a list of BTC-denominated JSON numbers in whole satoshis.
function sumSats(values) {
  return values.reduce((acc, v) => acc + Math.round(Number(v) * 1e8), 0);
}

// --- block page -------------------------------------------------------

export async function showBlock(container, ref, pageParam) {
  const my = ++epoch;
  renderLoading(container, 'Block');
  let hash = ref.hash;
  try {
    if (hash === undefined) {
      if (!/^\d+$/.test(ref.height ?? '')) {
        renderError(container, 'Block', `"${ref.height}" is not a block height.`);
        return;
      }
      hash = await rpc.call('getblockhash', [parseInt(ref.height, 10)]);
      if (my !== epoch) return;
    }
    const block = await rpc.call('getblock', [hash.toLowerCase(), 1]);
    if (my !== epoch) return;
    renderBlock(container, block, parseInt(pageParam, 10) || 1);
  } catch (e) {
    if (my !== epoch) return;
    renderError(container, 'Block', rpcErrorMessage(e));
  }
}

function blockStatusText(block) {
  if (block.confirmations === undefined) return 'not in this node’s block index';
  if (block.confirmations === -1) return 'not on the active chain (fork block)';
  return `${fmtInt(block.confirmations)} confirmation${block.confirmations === 1 ? '' : 's'}`;
}

function renderBlock(container, block, page) {
  const head = card('Block');

  const hero = el('div', 'hero');
  hero.appendChild(el('div', 'hero-height mono',
    block.height !== undefined ? `#${fmtInt(block.height)}` : 'height unknown'));
  const sub = el('div', 'hero-sub muted');
  sub.textContent = block.time
    ? `mined ${fmtAge(block.time)} ago · ${blockStatusText(block)}`
    : blockStatusText(block);
  hero.appendChild(sub);
  head.appendChild(hero);

  const kv = el('dl', 'kv');
  kv.appendChild(kvRow('hash', copyable(block.hash)));

  const prev = block.previousblockhash;
  if (prev && prev !== ZERO_HASH) {
    kv.appendChild(kvRow('previous block',
      link(`#/block/${prev}`, shortHash(prev))));
  } else {
    kv.appendChild(kvRow('previous block', el('span', 'muted', '— (genesis block)')));
  }
  kv.appendChild(kvRow('next block',
    block.nextblockhash
      ? link(`#/block/${block.nextblockhash}`, shortHash(block.nextblockhash))
      : el('span', 'muted', block.confirmations === -1 ? '—' : '— (chain tip)')));

  if (block.time) {
    kv.appendChild(kvRow('time',
      `${fmtTimestamp(block.time)} (${fmtAge(block.time)} ago)`));
  }
  if (block.mediantime) {
    kv.appendChild(kvRow('median time', fmtTimestamp(block.mediantime)));
  }
  kv.appendChild(kvRow('version',
    `${block.version}${block.versionHex ? ` (0x${block.versionHex})` : ''}`));
  kv.appendChild(kvRow('merkle root', copyable(block.merkleroot)));
  if (block.bits !== undefined) {
    kv.appendChild(kvRow('bits · difficulty',
      `${block.bits} · ${fmtDifficulty(block.difficulty)}`));
  }
  kv.appendChild(kvRow('nonce', fmtInt(block.nonce)));
  kv.appendChild(kvRow('size',
    `${fmtBytes(block.size)} (${fmtInt(block.size)} B · stripped ${fmtInt(block.strippedsize)} B)`));
  kv.appendChild(kvRow('weight · vsize',
    `${fmtInt(block.weight)} WU · ${fmtInt(Math.ceil(block.weight / 4))} vB`));
  if (block.chainwork) kv.appendChild(kvRow('chainwork', block.chainwork.replace(/^0+/, '') || '0'));
  kv.appendChild(kvRow('transactions', fmtInt(block.nTx)));
  head.appendChild(kv);

  const txCard = card(`Transactions (${fmtInt(block.nTx)})`);
  const txHolder = el('div');
  txCard.appendChild(txHolder);
  renderBlockTxPage(txHolder, block, page);

  container.replaceChildren(head, txCard);
}

// Lazy tx list: only the current page's rows exist in the DOM — mainnet
// blocks can hold thousands of txids.
function renderBlockTxPage(holder, block, pageRaw) {
  const txids = block.tx || [];
  const pages = Math.max(1, Math.ceil(txids.length / TXS_PER_PAGE));
  const page = Math.min(Math.max(1, pageRaw), pages);
  const start = (page - 1) * TXS_PER_PAGE;
  const slice = txids.slice(start, start + TXS_PER_PAGE);

  const table = el('table', 'txlist');
  const tbody = el('tbody');
  slice.forEach((txid, i) => {
    const n = start + i;
    const tr = el('tr');
    tr.appendChild(el('td', 'col-idx mono', `${n}`));
    const cell = el('td', 'col-txid');
    cell.appendChild(link(`#/tx/${txid}`, txid, 'xlink mono'));
    if (n === 0) cell.appendChild(pill('coinbase', 'pill-accent'));
    tr.appendChild(cell);
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);

  const wrap = el('div', 'table-wrap');
  wrap.appendChild(table);

  const goto = (p) => {
    replaceHash(`/block/${block.hash}${p > 1 ? `?page=${p}` : ''}`);
    renderBlockTxPage(holder, block, p);
  };
  holder.replaceChildren(wrap);
  if (pages > 1) {
    holder.prepend(pager(page, pages, goto));
    holder.appendChild(pager(page, pages, goto));
  }
}

function pager(page, pages, goto) {
  const nav = el('div', 'pager');
  const prev = el('button', 'btn', '‹ prev');
  prev.type = 'button';
  prev.disabled = page <= 1;
  prev.addEventListener('click', () => goto(page - 1));
  const next = el('button', 'btn', 'next ›');
  next.type = 'button';
  next.disabled = page >= pages;
  next.addEventListener('click', () => goto(page + 1));
  nav.append(prev, el('span', 'pager-label', `page ${fmtInt(page)} of ${fmtInt(pages)}`), next);
  return nav;
}

// --- tx page ----------------------------------------------------------

export async function showTx(container, txid) {
  const my = ++epoch;
  renderLoading(container, 'Transaction');
  if (!HASH64.test(txid || '')) {
    renderError(container, 'Transaction', `"${txid}" is not a txid (64 hex characters).`);
    return;
  }
  let tx;
  try {
    tx = await rpc.call('getrawtransaction', [txid.toLowerCase(), 1]);
  } catch (e) {
    if (my === epoch) renderError(container, 'Transaction', rpcErrorMessage(e));
    return;
  }
  if (my !== epoch) return;
  renderTx(container, tx, my);
}

function txIsCoinbase(tx) {
  return tx.vin.length === 1 && tx.vin[0].coinbase !== undefined;
}

function txSignalsRbf(tx) {
  return tx.vin.some((v) => v.coinbase === undefined && v.sequence < 0xfffffffe);
}

function txStatus(tx) {
  if (!tx.blockhash) return { text: 'unconfirmed — in the mempool', confirmed: false };
  if (tx.confirmations === undefined) {
    return { text: 'in a block unknown to this node’s index', confirmed: false };
  }
  if (tx.confirmations === 0) {
    return { text: 'in a block off the active chain (stale)', confirmed: false };
  }
  return {
    text: `confirmed · ${fmtInt(tx.confirmations)} confirmation${tx.confirmations === 1 ? '' : 's'}`,
    confirmed: true,
  };
}

function locktimeText(tx) {
  const lt = tx.locktime;
  if (!lt) return '0';
  const kind = lt < 500000000 ? 'block height' : fmtTimestamp(lt);
  const enforced = tx.vin.some((v) => v.sequence !== SEQUENCE_FINAL);
  return `${fmtInt(lt)} (${kind})${enforced ? '' : ' — not enforced, all sequences final'}`;
}

function renderTx(container, tx, my) {
  const coinbase = txIsCoinbase(tx);
  const status = txStatus(tx);
  const outSats = sumSats(tx.vout.map((o) => o.value));

  const head = card('Transaction');
  const badges = el('div', 'tx-badges');
  if (coinbase) badges.appendChild(pill('coinbase', 'pill-accent'));
  if (!coinbase && txSignalsRbf(tx)) {
    badges.appendChild(pill(status.confirmed ? 'RBF signaled' : 'replaceable (RBF)', 'pill-muted'));
  }
  if (badges.childElementCount > 0) head.appendChild(badges);

  const kv = el('dl', 'kv');
  kv.appendChild(kvRow('txid', copyable(tx.txid)));
  // Skip the redundant wtxid row when equal to txid, and the coinbase case
  // where the node reports the BIP141 all-zeros wtxid.
  if (tx.hash && tx.hash !== tx.txid && tx.hash !== ZERO_HASH) {
    kv.appendChild(kvRow('wtxid', copyable(tx.hash)));
  }
  kv.appendChild(kvRow('status', el('span', status.confirmed ? '' : 'muted', status.text)));
  if (tx.blockhash) {
    kv.appendChild(kvRow('included in block',
      link(`#/block/${tx.blockhash}`, shortHash(tx.blockhash))));
  }
  if (tx.blocktime) kv.appendChild(kvRow('block time', fmtTimestamp(tx.blocktime)));
  kv.appendChild(kvRow('version', `${tx.version}`));
  kv.appendChild(kvRow('locktime', locktimeText(tx)));
  kv.appendChild(kvRow('size', `${fmtInt(tx.size)} B · ${fmtInt(tx.vsize)} vB · ${fmtInt(tx.weight)} WU`));

  const feeValue = el('span', 'muted', coinbase
    ? `none — coinbase mints ${fmtBtc(outSats / 1e8)} (block subsidy + this block’s fees)`
    : 'resolving inputs…');
  kv.appendChild(kvRow('fee', feeValue));
  head.appendChild(kv);

  // Inputs card: rows render in chunks; prevout value/address cells are
  // patched as funding txs arrive.
  const inCard = card(`Inputs (${fmtInt(tx.vin.length)})`);
  const inputs = tx.vin.map((vin, i) => ({ vin, i, row: null, resolved: undefined }));
  const inList = el('div', 'io-list');
  const inFoot = el('div', 'io-total muted');
  appendChunked(inList, inputs, (entry) => inputRow(entry, coinbase));
  inCard.append(inList, inFoot);

  const outCard = card(`Outputs (${fmtInt(tx.vout.length)})`);
  const outList = el('div', 'io-list');
  appendChunked(outList, tx.vout.map((vout) => ({ vout })), (e) => outputRow(e.vout));
  const outFoot = el('div', 'io-total muted');
  outFoot.textContent = `total out ${fmtBtc(outSats / 1e8)}`;
  outCard.append(outList, outFoot);

  container.replaceChildren(head, inCard, outCard);

  if (!coinbase) {
    resolvePrevouts(inputs, outSats, my, {
      onFee: (feeSats) => {
        feeValue.className = '';
        feeValue.textContent =
          `${fmtSats(feeSats)} (${fmtBtc(feeSats / 1e8)}) · ${(feeSats / tx.vsize).toFixed(1)} sat/vB`;
        const inSats = outSats + feeSats;
        inFoot.textContent = `total in ${fmtBtc(inSats / 1e8)}`;
      },
      onNoFee: (why) => {
        feeValue.className = 'muted';
        feeValue.textContent = why;
      },
    });
  }
}

// Render ENTRIES via ROWFN in chunks of IO_CHUNK with a "show more" button,
// so a million-output oddity never freezes the tab.
function appendChunked(list, entries, rowFn) {
  let shown = 0;
  const showNext = () => {
    const upto = Math.min(entries.length, shown + IO_CHUNK);
    for (; shown < upto; shown += 1) list.appendChild(rowFn(entries[shown]));
    if (shown < entries.length) {
      const more = el('button', 'btn io-more',
        `show ${fmtInt(Math.min(IO_CHUNK, entries.length - shown))} more of ${fmtInt(entries.length - shown)}`);
      more.type = 'button';
      more.addEventListener('click', () => { more.remove(); showNext(); });
      list.appendChild(more);
    }
  };
  showNext();
}

function ioRowSkeleton(index) {
  const row = el('div', 'io-row');
  row.appendChild(el('span', 'io-idx mono muted', `#${index}`));
  const main = el('div', 'io-main');
  const value = el('span', 'io-value mono');
  row.append(main, value);
  return { row, main, value };
}

function inputRow(entry, coinbase) {
  const { vin, i } = entry;
  const { row, main, value } = ioRowSkeleton(i);
  entry.row = { main, value };

  if (vin.coinbase !== undefined) {
    main.appendChild(el('div', '', coinbase
      ? 'coinbase — newly generated coins'
      : 'coinbase input'));
    main.appendChild(reveal('coinbase script', [['hex', vin.coinbase]]));
    value.textContent = '—';
  } else {
    const line = el('div');
    line.appendChild(link(`#/tx/${vin.txid}`, `${shortId(vin.txid, 10)}:${vin.vout}`, 'xlink mono'));
    main.appendChild(line);
    const addr = el('div', 'io-addr muted', 'resolving prevout…');
    main.appendChild(addr);
    entry.addrEl = addr;
    const blocks = [
      ['scriptSig hex', vin.scriptSig?.hex],
      ['scriptSig asm', vin.scriptSig?.asm],
    ];
    if (vin.txinwitness) {
      vin.txinwitness.forEach((item, k) => blocks.push([`witness [${k}]`, item || '(empty)']));
    }
    if (blocks.some(([, t]) => t)) main.appendChild(reveal('scriptSig / witness', blocks));
    applyResolved(entry);
  }
  main.appendChild(el('div', 'io-sub',
    `sequence ${vin.sequence}${vin.coinbase === undefined && vin.sequence < 0xfffffffe ? ' · signals RBF' : ''}`));
  return row;
}

// Write a resolved (or failed) prevout into an input row, if rendered yet.
function applyResolved(entry) {
  if (!entry.row || entry.resolved === undefined) return;
  const { value } = entry.row;
  if (entry.resolved === null) {
    entry.addrEl.textContent =
      entry.noResolveWhy || 'prevout unavailable (funding tx not in mempool/txindex)';
    value.textContent = '?';
    value.classList.add('muted');
  } else {
    const { value: btc, scriptPubKey } = entry.resolved;
    entry.addrEl.classList.remove('muted');
    entry.addrEl.replaceChildren(
      scriptPubKey.address
        ? copyable(scriptPubKey.address, shortId(scriptPubKey.address, 14))
        : el('span', 'muted', scriptPubKey.type));
    value.textContent = fmtBtc(btc);
  }
}

function outputRow(vout) {
  const { row, main, value } = ioRowSkeleton(vout.n);
  const spk = vout.scriptPubKey || {};
  const line = el('div');
  if (spk.address) {
    line.appendChild(copyable(spk.address, spk.address));
  } else {
    line.appendChild(el('span', 'muted',
      spk.type === 'nulldata' ? 'OP_RETURN (nulldata)' : (spk.type || 'unknown')));
  }
  main.appendChild(line);
  main.appendChild(el('div', 'io-sub', spk.type || ''));
  main.appendChild(reveal('script', [
    ['type', spk.type],
    ['hex', spk.hex],
    ['asm', spk.asm],
  ]));
  value.textContent = fmtBtc(vout.value);
  return row;
}

// Fetch each distinct funding tx (batched); patch input rows as results
// arrive; report the fee only when every input's prevout resolved.
// OUTSATS is the caller's already-summed output total in satoshis.
async function resolvePrevouts(inputs, outSats, my, { onFee, onNoFee }) {
  const spends = inputs.filter((e) => e.vin.coinbase === undefined);
  // Group inputs by funding txid so each batch result patches exactly the
  // rows it funds (a tx can spend many outputs of one funding tx).
  const byTxid = new Map();
  for (const entry of spends) {
    const list = byTxid.get(entry.vin.txid);
    if (list) list.push(entry);
    else byTxid.set(entry.vin.txid, [entry]);
  }
  const uniq = [...byTxid.keys()];
  const capped = uniq.slice(0, MAX_PREVOUT_TXS);

  for (let at = 0; at < capped.length; at += PREVOUT_BATCH) {
    const chunk = capped.slice(at, at + PREVOUT_BATCH);
    let results;
    try {
      results = await rpc.batch(chunk.map((id) => ['getrawtransaction', [id, 1]]));
    } catch {
      results = chunk.map(() => ({ result: null, error: { message: 'unreachable' } }));
    }
    if (my !== epoch) return;
    chunk.forEach((id, k) => {
      const prev = results[k].error ? null : results[k].result;
      for (const entry of byTxid.get(id)) {
        entry.resolved = prev?.vout?.[entry.vin.vout] ?? null;
        applyResolved(entry);
      }
    });
  }

  if (uniq.length > MAX_PREVOUT_TXS) {
    for (const entry of spends) {
      if (entry.resolved === undefined) {
        entry.resolved = null;
        entry.noResolveWhy = 'not resolved — transaction spends too many distinct funding txs';
        applyResolved(entry);
      }
    }
    onNoFee(`unavailable — only the first ${MAX_PREVOUT_TXS} funding txs were resolved`);
    return;
  }
  if (spends.some((e) => e.resolved === null)) {
    onNoFee('unavailable — some prevouts could not be resolved (node may lack -txindex)');
    return;
  }
  const inSats = sumSats(spends.map((e) => e.resolved.value));
  const fee = inSats - outSats;
  if (fee < 0) onNoFee('unavailable — inputs resolved to less than the outputs (inconsistent data)');
  else onFee(fee);
}

// --- universal search ---------------------------------------------------

// Digits -> height (getblockhash); 64 hex -> block hash first, then txid —
// one batched round trip. A 64-char all-digit string can never be a real
// height, so the hash test runs first. Returns { ok } after navigating, or
// { ok: false, message } for the graceful not-found state.
export async function search(qRaw) {
  const q = qRaw.trim();
  if (!q) return { ok: false, message: 'Enter a block height, block hash, or txid.' };

  if (/^\d+$/.test(q) && !HASH64.test(q)) {
    try {
      const hash = await rpc.call('getblockhash', [parseInt(q, 10)]);
      navigate(`/block/${hash}`);
      return { ok: true };
    } catch (e) {
      return { ok: false, message: `No block at height ${q} — ${rpcErrorMessage(e)}` };
    }
  }

  if (HASH64.test(q)) {
    const h = q.toLowerCase();
    let blockR;
    let txR;
    try {
      [blockR, txR] = await rpc.batch([
        ['getblockheader', [h, true]],
        ['getrawtransaction', [h, 0]],
      ]);
    } catch (e) {
      return { ok: false, message: rpcErrorMessage(e) };
    }
    if (!blockR.error) {
      navigate(`/block/${h}`);
      return { ok: true };
    }
    if (!txR.error) {
      navigate(`/tx/${h}`);
      return { ok: true };
    }
    return {
      ok: false,
      message: 'Not found: no block or transaction with this hash on this node '
        + '(confirmed txs need -txindex to be searchable).',
    };
  }

  return {
    ok: false,
    message: 'Unrecognized query — use a block height (digits) or a block hash / txid (64 hex characters).',
  };
}
