// Human formatting helpers. All display-only; raw values stay in the data.

export function fmtInt(n) {
  if (n === null || n === undefined || Number.isNaN(n)) return '—';
  return Number(n).toLocaleString('en-US');
}

export function fmtBytes(n) {
  if (n === null || n === undefined || Number.isNaN(n)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = Number(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function fmtRate(bytesPerSec) {
  if (bytesPerSec === null || Number.isNaN(bytesPerSec)) return '';
  return `${fmtBytes(bytesPerSec)}/s`;
}

// "42s", "7m 03s", "5h 12m", "3d 4h"
export function fmtDuration(secs) {
  if (secs === null || secs === undefined || Number.isNaN(secs)) return '—';
  const s = Math.max(0, Math.round(secs));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, '0')}s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${String(m % 60).padStart(2, '0')}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}

export function fmtAge(unixTime, nowMs = Date.now()) {
  if (!unixTime) return '—';
  return fmtDuration(nowMs / 1000 - unixTime);
}

// BTC/kvB (Core fee-rate JSON convention) -> "N.N sat/vB"
export function fmtFeeRate(btcPerKvb) {
  if (btcPerKvb === null || btcPerKvb === undefined) return '—';
  const satPerVb = (btcPerKvb * 1e8) / 1000;
  return `${satPerVb.toFixed(satPerVb < 10 ? 2 : 0)} sat/vB`;
}

export function fmtPct(fraction) {
  if (fraction === null || fraction === undefined || Number.isNaN(fraction)) return '—';
  const p = Math.min(100, Math.max(0, fraction * 100));
  return `${p >= 99.995 ? '100' : p.toFixed(2)}%`;
}

// Block hashes are all leading zeros up front; keep the tail, which is the
// distinctive part.
export function shortHash(hash, tail = 16) {
  if (!hash) return '—';
  return hash.length <= tail ? hash : `…${hash.slice(-tail)}`;
}

// Txids/addresses are distinctive at both ends; keep head and tail.
export function shortId(id, ends = 10) {
  if (!id) return '—';
  return id.length <= 2 * ends + 1 ? id : `${id.slice(0, ends)}…${id.slice(-ends)}`;
}

// The RPC's BTC-denominated JSON number, shown with full 8-decimal precision
// (rounded to whole satoshis first so float noise never leaks into amounts).
export function fmtBtc(btc) {
  if (btc === null || btc === undefined || Number.isNaN(btc)) return '—';
  return `${(Math.round(Number(btc) * 1e8) / 1e8).toFixed(8)} BTC`;
}

export function fmtSats(sats) {
  if (sats === null || sats === undefined || Number.isNaN(sats)) return '—';
  return `${fmtInt(sats)} sat`;
}

// Absolute wall-clock form of a unix timestamp, viewer's locale + timezone.
export function fmtTimestamp(unixTime) {
  if (!unixTime) return '—';
  return new Date(unixTime * 1000).toLocaleString();
}

export function fmtDifficulty(d) {
  if (d === null || d === undefined || Number.isNaN(d)) return '—';
  const n = Number(d);
  if (n >= 1000) return n.toLocaleString('en-US', { maximumFractionDigits: 0 });
  if (n >= 1) return n.toLocaleString('en-US', { maximumFractionDigits: 4 });
  return n.toPrecision(6);
}
