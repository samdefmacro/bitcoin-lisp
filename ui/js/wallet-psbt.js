// PSBT operations + fee bump (gui-plan P6c).
//
// Ported from Core's Qt: src/qt/psbtoperationsdialog.{h,cpp} for the panel,
// and transactionview.cpp's "Increase transaction fee" for the bump. As in
// 6d we keep the LOGIC and drop the widgets — an inline panel on its own tab
// rather than a modal, so the node harness can drive it as real DOM.
//
// RPC shapes consumed here (src/rpc/psbt.lisp):
//
//   decodepsbt [psbt] -> { tx: <decoded unsigned tx>, inputs: [...],
//     outputs: [...] }; tx.vout[].scriptPubKey.address is what the panel
//     renders, and inputs[].witness_utxo / .non_witness_utxo carry the
//     prevout whose ownership decides whether we could sign.
//   analyzepsbt [psbt] -> { inputs: [{ has_utxo, is_final, next }],
//     fee?, next } where `next` is Core's PSBTAnalysis.next role. `fee` is
//     ABSENT when any input amount is unknown — which is exactly Core's
//     "Unable to calculate transaction fee" condition, not an error.
//   walletprocesspsbt [psbt, sign, sighashtype, bip32derivs, finalize]
//     -> { psbt, complete, hex? }.
//   finalizepsbt [psbt, extract] -> { psbt?, hex?, complete }.
//   sendrawtransaction [hex] -> txid.
//   bumpfee / psbtbumpfee [txid, options] -> { txid|psbt, origfee, fee,
//     errors }.
//
// NOTE ON `couldSign`. Core reads n_could_sign out of fillPSBT(sign=false)
// (psbtoperationsdialog.cpp:62) to tell "needs signatures" from "needs
// signatures, but not yours". We have no RPC that reports that count, so the
// panel derives it the same way the node itself does in %psbt-coins-map:
// resolve each input's prevout address and ask getaddressinfo whether it is
// ours and solvable. Same question, one round trip per distinct address,
// batched.

import { fmtBtc } from './format.js';

// --- status (Core PSBTOperationsDialog::showTransactionStatus) ----------

// Core's StatusLevel. 'err' is reserved for a genuinely unknown state, the
// way Core reserves it — a PSBT that merely needs more work is not an error.
export const LEVEL = { INFO: 'info', WARN: 'warn', ERR: 'err' };

// Verbatim from psbtoperationsdialog.cpp:262-296. The sub-cases under
// `signer` are the useful part: "still needs signatures" reads very
// differently once you know THIS wallet can never provide them.
export function psbtStatus(analysis,
  { hasWallet, privateKeysDisabled, couldSign, complete }) {
  let next = analysis && analysis.next;
  // Our analyzepsbt calls an input `finalizer` as soon as it carries any
  // partial signature, where Core's role means fully signed. When
  // finalizepsbt — which actually tries — says it is not finalizable, the
  // honest status is "still needs signatures", not "ready for broadcast".
  // `complete` undefined means "not probed", and the role stands.
  if (complete === false && (next === 'finalizer' || next === 'extractor')) {
    next = 'signer';
  }
  if (next === 'updater') {
    return {
      text: 'Transaction is missing some information about inputs.',
      level: LEVEL.WARN,
    };
  }
  if (next === 'signer') {
    let text = 'Transaction still needs signature(s).';
    let level = LEVEL.INFO;
    if (!hasWallet) {
      text += ' (But no wallet is loaded.)';
      level = LEVEL.WARN;
    } else if (privateKeysDisabled) {
      text += ' (But this wallet cannot sign transactions.)';
      level = LEVEL.WARN;
    } else if (!couldSign) {
      text += ' (But this wallet does not have the right keys.)';
      level = LEVEL.WARN;
    }
    return { text, level };
  }
  if (next === 'finalizer' || next === 'extractor') {
    return {
      text: 'Transaction is fully signed and ready for broadcast.',
      level: LEVEL.INFO,
    };
  }
  return { text: 'Transaction status is unknown.', level: LEVEL.ERR };
}

// Core: psbtoperationsdialog.cpp:69 — all three conditions, and note the
// wallet must be able to sign at least one input. Offering a Sign button
// that cannot change anything is worse than not offering it.
export function signEnabled({ complete, hasWallet, privateKeysDisabled, couldSign }) {
  return !!hasWallet && !complete && !privateKeysDisabled && couldSign > 0;
}

// Core: psbtoperationsdialog.cpp:74 — broadcast is gated on completeness
// alone; a complete PSBT is broadcastable even by a watch-only wallet.
export function broadcastEnabled(complete) {
  return !!complete;
}

// A PSBT is complete when nothing is left to sign — Core computes this with
// FinalizePSBT before deciding. analyzepsbt's terminal roles say the same:
// `finalizer` means every input has its signatures, `extractor` means it is
// already finalized.
export function psbtComplete(analysis) {
  const next = analysis && analysis.next;
  return next === 'finalizer' || next === 'extractor';
}

// --- rendering (Core PSBTOperationsDialog::renderTransaction) ------------

// One line per output, "Sends X to ADDR", flagged when the destination is
// ours. ISMINE maps address -> boolean; an address we could not resolve is
// simply not flagged, never guessed.
export function psbtOutputs(decoded, isMine = {}) {
  const vout = (decoded && decoded.tx && decoded.tx.vout) || [];
  return vout.map((out) => {
    const spk = out.scriptPubKey || {};
    const address = spk.address || null;
    return {
      address,
      value: out.value,
      mine: !!(address && isMine[address]),
      // Core renders the raw script when there is no address to show.
      script: spk.hex || null,
    };
  });
}

// Core: "Transaction has N unsigned input(s)." — the count of inputs whose
// analysis says they are not final yet.
export function unsignedInputCount(analysis) {
  const inputs = (analysis && analysis.inputs) || [];
  return inputs.filter((i) => !i.is_final).length;
}

// DELIBERATELY NOT bug-compatible with the line it mirrors. Core prints
// "Unable to calculate transaction fee or total transaction amount." on
// `if (!*analysis.fee)` (psbtoperationsdialog.cpp:197), which dereferences
// the optional and so actually tests fee == 0 — a genuinely zero-fee PSBT
// reports as uncalculable there. analyzepsbt OMITS the key when an input
// amount is unknown, so hasOwn distinguishes the two cases correctly: a real
// zero fee renders as a fee.
export function psbtFee(analysis) {
  return analysis && Object.hasOwn(analysis, 'fee') ? analysis.fee : null;
}

export function feeLine(analysis) {
  const fee = psbtFee(analysis);
  return fee === null
    ? 'Unable to calculate transaction fee or total transaction amount.'
    : `Pays transaction fee: ${fmtBtc(fee)}`;
}

// --- input ownership, for couldSign -------------------------------------

// The prevout address of each PSBT input, from whichever UTXO field the
// input carries. Returns nulls in place for inputs we cannot resolve, so the
// caller can distinguish "not ours" from "unknown".
export function psbtInputAddresses(decoded) {
  const inputs = (decoded && decoded.inputs) || [];
  const vin = (decoded && decoded.tx && decoded.tx.vin) || [];
  return inputs.map((input, i) => {
    if (input.witness_utxo && input.witness_utxo.scriptPubKey) {
      return input.witness_utxo.scriptPubKey.address || null;
    }
    // non_witness_utxo is the whole previous transaction; the relevant
    // output is the one this input spends.
    const prev = input.non_witness_utxo;
    const n = vin[i] && vin[i].vout;
    if (prev && prev.vout && Number.isInteger(n) && prev.vout[n]) {
      const spk = prev.vout[n].scriptPubKey || {};
      return spk.address || null;
    }
    return null;
  });
}

// Core's n_could_sign: how many inputs THIS wallet could still contribute a
// signature to. Two exclusions matter beyond ownership:
//   - an input that is already final needs nothing from us, so counting it
//     would offer a Sign button whose click is a no-op round trip;
//   - an input whose prevout script has no address (bare multisig, say) is
//     unresolvable here and so is not counted — a false negative, which
//     costs a missing button rather than a wrong one.
export function countSignable(analysis, inputAddresses, infos) {
  const inputs = (analysis && analysis.inputs) || [];
  return inputAddresses.filter((address, i) => {
    if (!address) return false;
    if (inputs[i] && inputs[i].is_final) return false;
    const info = infos[address];
    return !!(info && info.ismine && info.solvable);
  }).length;
}

// --- fee bump (Core transactionview.cpp "Increase transaction fee") ------

// Core enables the bump only for a wallet transaction it can actually
// replace. From what gettransaction gives us that is: our own outgoing
// transaction, still unconfirmed, not abandoned, and signalling BIP125.
// `bip125-replaceable` is "yes" | "no" | "unknown" (unknown means we do not
// have the parent transactions to decide, so we must not offer it).
export function bumpEligible(tx) {
  if (!tx) return false;
  if ((tx.confirmations ?? 0) !== 0) return false;
  if (tx['bip125-replaceable'] !== 'yes') return false;
  // Already bumped: the node refuses ("Cannot bump transaction X which was
  // already bumped by Y"), and the original stays unconfirmed and
  // replaceable-looking in the history, so without this the row keeps
  // offering a bump that can only fail.
  if (tx.replaced_by_txid) return false;
  const details = tx.details || [];
  const isSend = details.some((d) => d.category === 'send');
  const abandoned = details.some((d) => d.abandoned);
  return isSend && !abandoned;
}

// bumpfee signs and broadcasts; psbtbumpfee returns a PSBT instead. A
// watch-only wallet has no choice — the node refuses bumpfee outright
// ("bumpfee is not available with wallets that have private keys disabled").
export function bumpMethod(privateKeysDisabled) {
  return privateKeysDisabled ? 'psbtbumpfee' : 'bumpfee';
}

export function bumpParams(txid, feeRate) {
  // Core's bumpfee takes an options object; fee_rate is in sat/vB. Omitted
  // entirely when blank so the node picks its own increment rather than
  // being handed a zero.
  return feeRate ? [txid, { fee_rate: Number(feeRate) }] : [txid];
}

// --- input sanitation ----------------------------------------------------

// Trim and sanity-check a pasted PSBT before spending a round trip on it.
// Base64 PSBTs always start with the magic "cHNidP" ("psbt\xff" encoded), so
// a paste that lost its prefix or picked up a hex dump is caught here with a
// useful message instead of a generic decode error.
export function normalizePsbt(text) {
  const s = (text || '').replace(/\s+/g, '');
  if (!s) return { error: 'Paste a base64 PSBT.' };
  if (!s.startsWith('cHNidP')) {
    return { error: 'That does not look like a base64 PSBT (it should start with "cHNidP").' };
  }
  return { psbt: s };
}
