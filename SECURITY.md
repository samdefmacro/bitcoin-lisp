# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security bug.** Use GitHub's private
vulnerability reporting on this repository: the **Security** tab →
**Report a vulnerability**. That opens a private advisory visible only to the
maintainers.

Please include: what you observed, the smallest input or sequence that
reproduces it, which network (mainnet / testnet4 / signet / regtest) and which
commit you ran, and what you believe the impact is.

There is no bug bounty. Expect an acknowledgement within a week.

## What is in scope

This is a from-scratch Bitcoin full node in Common Lisp. The most valuable
reports are the ones where **this node disagrees with Bitcoin Core**, because
that is a chain split for anyone running it:

- a block or transaction we accept and Core rejects, or the reverse;
- any divergence in script evaluation, sighash, or a consensus limit;
- remote crashes, memory exhaustion, or unbounded work driven by a peer;
- a wallet bug that can lose funds or sign something the operator did not
  intend.

Divergences in policy (relay, mempool limits, fee estimation) are worth
reporting too, but they are not chain splits — say which you believe you have
found.

## What this software is

Consensus-critical code here is written against Bitcoin Core as the
specification (`refs/bitcoin/`), and the project's own gap analyses have
repeatedly found real divergences — several of them chain splits — after the
node was already running on mainnet. **Treat it as experimental.** Do not put
funds on it that you are not prepared to lose, and do not rely on it as your
only source of truth for a payment.
