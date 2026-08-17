// Wallet lifecycle + encryption UI (gui-plan P6d; see gui-plan §5.1 for the
// Bitcoin Core cross-reference this is ported from).
//
// Core's Qt does all of this in src/qt/askpassphrasedialog.{h,cpp} (one dialog,
// four modes), src/qt/walletmodel.{h,cpp} (EncryptionStatus + UnlockContext)
// and src/qt/createwalletdialog.{h,cpp}. We keep the LOGIC and drop the
// widgets: inline panels rather than modals, because the page is already a
// tab strip and the node test harness drives real DOM, not a dialog polyfill.
//
// RPC shapes consumed here are what src/rpc/wallet-crypt.lisp emits:
//
//   encryptwallet [passphrase] -> instruction STRING (not null). Leaves the
//     wallet LOCKED and rotates the HD seed, so every cached address in the
//     page is stale afterwards -> full refresh, not a partial one.
//   walletpassphrase [passphrase, timeout] -> null; -14 wrong passphrase,
//     -15 wallet is not encrypted, -8 bad/negative timeout or empty pass.
//   walletpassphrasechange [old, new] -> null; -14 on a wrong old passphrase.
//     Does NOT re-encrypt any key and does NOT reset a pending relock.
//   walletlock [] -> null; -15 when the wallet is not encrypted.
//   backupwallet [destination] -> null; every failure is -4 with one message.
//   restorewallet [name, backup_file, load_on_startup?] -> { name, warnings? }.
//   createwallet [name, disable_private_keys, blank, passphrase, avoid_reuse]
//     -> { name, warnings? }; a passphrase with private keys disabled is -4.
//   unloadwallet [name] -> { warnings? }.
//
// SECURITY NOTE — this is the one thing that does NOT transfer from Qt.
// Qt is in-process: the passphrase lives in a SecureString and never leaves
// the program. Ours crosses HTTP to the RPC, and JavaScript cannot truly
// scrub a string — clearing an input's .value drops one reference, it does
// not erase the copies the engine may still hold. So `forgetPassphrase`
// below is hygiene, NOT a guarantee, and the real bound on the risk is the
// deployment constraint in gui-plan §4 (loopback, or inside an SSH tunnel).
// The UI says so out loud rather than letting a Core-shaped dialog imply
// Core-grade handling.

import { fmtDuration } from './format.js';

// --- pure helpers (exported for tests) --------------------------------

// Core's WalletModel::EncryptionStatus (walletmodel.h:67-73), derived from
// getwalletinfo. It takes TWO fields, and the order matters:
//
//   NoKeys       private_keys_enabled === false   <- checked FIRST
//   Unencrypted  `unlocked_until` key ABSENT
//   Locked       unlocked_until === 0
//   Unlocked     unlocked_until > 0
//
// `unencrypted` is the ABSENCE of the key rather than 0, because 0 already
// means encrypted-but-locked (src/rpc/wallet.lisp emits the field only for
// encrypted wallets). NoKeys dominates: a watch-only wallet must offer no
// encryption controls at all, whatever else the object says.
export function encryptionState(info) {
  if (!info) return 'unknown';
  if (info.private_keys_enabled === false) return 'no-keys';
  if (!Object.hasOwn(info, 'unlocked_until')) return 'unencrypted';
  return info.unlocked_until === 0 ? 'locked' : 'unlocked';
}

export function isEncrypted(state) {
  return state === 'locked' || state === 'unlocked';
}

// Chip label + variant per state. Qt shows a padlock in the status bar, open
// or closed; same semantics in the page's existing pill vocabulary. `bad` for
// unlocked is not an error — it is the state where key material is reachable
// right now, the one you want to notice and end, which is exactly what Qt's
// open padlock signals.
export const STATE_UI = {
  unknown: { label: 'unknown', variant: 'pill-muted' },
  'no-keys': { label: 'watch-only', variant: 'pill-muted' },
  unencrypted: { label: 'not encrypted', variant: 'pill-accent' },
  locked: { label: 'locked', variant: 'pill-good' },
  unlocked: { label: 'unlocked', variant: 'pill-bad' },
};

// Seconds remaining on a walletpassphrase timeout, floored at 0. `until` is
// the wall-clock unix time the node scheduled the relock for; the node is
// authoritative, so a clock skewed against it only mis-renders the countdown
// and never changes what is actually permitted.
export function unlockSecondsLeft(info, nowMs = Date.now()) {
  const until = info?.unlocked_until;
  if (!until) return 0;
  return Math.max(0, until - Math.floor(nowMs / 1000));
}

// Same shape peers.js renders a ban expiry with — one duration format for the
// whole app, and fmtDuration already handles the tails (>=48h, NaN) that a
// bogus unlocked_until could otherwise walk into.
export function unlockCountdown(info, nowMs = Date.now()) {
  const left = unlockSecondsLeft(info, nowMs);
  return left > 0 ? fmtDuration(left) : '';
}

// Core's unlock timeouts, as offered by the Qt dialog's spinner and
// bitcoin-cli docs. The node clamps anything above MAX_SLEEP_TIME itself.
export const UNLOCK_TIMEOUTS = [
  [60, '1 minute'],
  [300, '5 minutes'],
  [900, '15 minutes'],
  [3600, '1 hour'],
  [28800, '8 hours'],
];
export const DEFAULT_UNLOCK_TIMEOUT = 300;

// The two-field confirm is a FRONTEND concern — there is no RPC for it and
// there should not be. Core: askpassphrasedialog.cpp:154 "The supplied
// passphrases do not match."
export function validatePassphrasePair(a, b) {
  if (!a) return 'Enter a passphrase.';
  if (a !== b) return 'The supplied passphrases do not match.';
  return null;
}

export function validateTimeout(raw) {
  const n = Number(raw);
  if (!Number.isInteger(n)) return 'Timeout must be an integer.';
  if (n < 0) return 'Timeout cannot be negative.';
  return null;
}

// Core's own strength hint (askpassphrasedialog.cpp:42). Advisory only —
// deliberately NOT enforced, because refusing a passphrase the node would
// accept is its own failure mode.
export const PASSPHRASE_HINT =
  'Use ten or more random characters, or eight or more words.';

export const ENCRYPT_WARNING =
  'If you encrypt your wallet and lose your passphrase, you will LOSE ALL OF YOUR BITCOINS.';

// encryptwallet rotates the HD seed, so anything derived before it is not in
// the new backup. Core says this twice (before and after); so do we.
export const ENCRYPT_BACKUP_WARNING =
  'Encrypting generates a new HD seed. Any backup you made before this will '
  + 'not cover addresses generated afterwards — take a fresh backup once it '
  + 'completes.';

// --- RPC parameter builders (exported for tests) -----------------------

// Only the builders that carry LOGIC live here — a function that returns
// its arguments in a list is an indirection, not a seam. The timeout
// coercion below is load-bearing (a <select> yields a string), and
// createParams distinguishes "no passphrase" from the empty string.
export function unlockParams(passphrase, timeout) {
  return [passphrase, Number(timeout)];
}

// createwallet is positional: [name, disable_private_keys, blank, passphrase,
// avoid_reuse]. The passphrase slot is only filled when non-empty — an empty
// string is a DIFFERENT request (the node warns "wallet will not be
// encrypted") and we should not send it by accident.
export function createParams({
  name, disablePrivateKeys = false, blank = false, passphrase = '', avoidReuse = false,
}) {
  return [name, !!disablePrivateKeys, !!blank, passphrase || null, !!avoidReuse];
}

// Mirrors the node's own refusal (src/rpc/wallet.lisp rpc-createwallet) so
// the form can say so before a round trip.
export function validateCreate({ name, disablePrivateKeys, passphrase, confirm }) {
  if (!name) return 'Wallet name cannot be empty.';
  if (!/^[A-Za-z0-9._-]+$/.test(name) || name === '.' || name === '..') {
    return 'Invalid wallet name — use letters, digits, dot, underscore or dash.';
  }
  if (passphrase && disablePrivateKeys) {
    return 'Passphrase provided but private keys are disabled. A passphrase is '
      + 'only used to encrypt private keys.';
  }
  if (passphrase) return validatePassphrasePair(passphrase, confirm);
  return null;
}

// --- the UnlockContext port -------------------------------------------
//
// Core's WalletModel::requestUnlock (walletmodel.cpp:428-446) returns an RAII
// object: it prompts when the wallet is locked, reports invalid if the user
// cancelled or mistyped, and — the part worth having — RELOCKS ON DESTRUCTION
// IFF the wallet was locked when the operation began. Borrow the unlock, hand
// it back.
//
// The obvious browser alternative (run the operation, catch -13, prompt,
// retry) is reactive and leaves the wallet unlocked afterwards, which is how
// "I unlocked for ten minutes to send one payment and forgot" happens.
//
// Cancellation THROWS rather than returning a sentinel. A `{cancelled:true}`
// return is indistinguishable from a successful RPC result unless every
// caller remembers to check it — and the callers 6c adds return objects
// (bumpfee -> {txid, origfee, fee}), so a forgotten check would render a
// cancelled bump as a successful one with an undefined txid. Throwing means
// a caller that forgets gets it rendered through the existing error path.
export class UnlockCancelled extends Error {
  constructor() {
    super('Cancelled — the wallet is locked.');
    this.name = 'UnlockCancelled';
  }
}

// `deps.state()` resolves to a CURRENT getwalletinfo object — it is awaited,
// and callers are expected to re-read it rather than hand over whatever the
// page happens to be holding. A stale object is the dangerous case: a tab
// that never fetched getwalletinfo yields `unknown`, which would skip the
// gate entirely and let a locked wallet fall through to a raw -13.
// `deps.prompt()` resolves true once the wallet has been unlocked (false if
// the user cancelled), and `deps.lock()` performs walletlock.
export async function withUnlocked(deps, fn) {
  // Anything but `locked` needs no unlock and must not be relocked
  // afterwards — including watch-only, for which Core returns a valid
  // non-relocking context because old versions could produce watch-only
  // wallets carrying encryption keys that do nothing.
  if (encryptionState(await deps.state()) !== 'locked') return fn();
  if (!(await deps.prompt())) throw new UnlockCancelled();
  // Core re-reads after the dialog and treats "still locked" as a cancel, so
  // a dismissed or mistyped prompt cannot fall through.
  if (encryptionState(await deps.state()) === 'locked') throw new UnlockCancelled();
  try {
    return await fn();
  } finally {
    await deps.lock();
  }
}

// Best-effort only — see the SECURITY NOTE at the top of this file. Dropping
// the reference is all JavaScript can do; it is not erasure.
export function forgetPassphrase(...inputs) {
  for (const input of inputs) {
    if (input) input.value = '';
  }
}
