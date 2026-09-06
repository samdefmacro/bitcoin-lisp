(in-package #:bitcoin-lisp)

#+sbcl
(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-sprof))

;;;; The node (Core init.cpp / bitcoind.cpp), one file per concern, loaded in
;;;; this order (state.lisp, the node struct, loads much earlier -- right after
;;;; config.lisp): params, notify, datadir, rpc-config, logging, entropy,
;;;; housekeeping, eviction, recovery, listen, mempool-persist, assumeutxo,
;;;; shutdown, indexes, flush, reindex, wallet-hooks, peers, sync, init.

;;;; Network parameters, ports, seeds, exit codes and the other constants
;;;; every later file may name; the entry point itself is init.lisp.

;;;; Network Configuration

(defconstant +sync-ticks-per-second+ 5
  "How finely the sync thread's between-cycle wait is sliced.

The wait exists to pump peer messages while nothing else is due, and the SLEEP
runs before the pump — so the tick length is the floor on how fast an announced
block can be noticed, and a propagation spans two ticks. At one tick per second
diag/propagation_probe.py measured a flat 2s on regtest for a block that takes
0.01s to mine.

Five is a bound, not a tuning: everything in that loop which wants a per-second
cadence is gated on the derived SECOND rather than on the tick, so shortening
the tick cannot make the trickle, ping or dump work run more often. Core's
ProcessMessages runs continuously; this moves in that direction without giving
up the loop's shape.")

(defconstant +testnet3+ :testnet3)
(defconstant +testnet4+ :testnet4)
(defconstant +signet+ :signet)
(defconstant +mainnet+ :mainnet)

(defconstant +regtest+ :regtest)

(defvar *connect-nodes* '()
  "-connect targets (Core m_specified_outgoing): peer specs to dial and keep
dialed, and NOTHING else. Deliberately not the node's added-nodes list, because
getaddednodeinfo reports -addnode and not -connect, exactly as Core's does —
both are nonetheless dialed as MANUAL connections.")

(defvar *pending-test-connections* '()
  "Connections the addconnection RPC has asked for, as (address . conn-type),
drained by the sync thread. A queue rather than a direct dial because node-peers
is single-writer by design; Core's own AddConnection likewise returns before the
connection completes. Regtest-only, like the RPC.")

(defvar *seed-nodes* '()
  "-seednode targets (Core connOptions.vSeedNodes): peers dialed once, purely to
collect addresses, and disconnected as soon as they deliver some. Core queues
them as m_addr_fetches and opens ConnectionType::ADDR_FETCH connections; the
disconnect lives in the addr handler, next to Core's.")

(defvar *use-addrman-outgoing* t
  "Core's CConnman m_use_addrman_outgoing (net.h:1095). NIL once -connect was
given in any form. A global rather than a node slot for the same reason
*dns-seed-enabled* and *block-notify-command* are: it is start-up configuration
that never varies within a run.")

(defun addrman-outgoing-enabled-p ()
  "Whether this node may open outbound connections of its own choosing (Core
CConnman::GetUseAddrmanOutgoing, net.h:1168).

NIL once -connect was given in ANY form: with -connect=<addr> Core's
ThreadOpenConnections takes the specified-addresses branch and never reaches
the addrman code at all, and with -connect=0 the thread is not started
(net.cpp:3540) — so no feeler, no block-relay slot, no replacement dial. Only
the MANUAL connections (-connect and -addnode) remain."
  *use-addrman-outgoing*)

(defun listen-port (network)
  "The P2P LISTEN port: -port when given, else NETWORK's default (Core
GetListenPort, net.cpp:138-162). Dialing peers keeps the chain default —
Core's -port only moves the listening/advertised side."
  (or *p2p-port-override* (network-port network)))

(defvar *mainnet-relay-enabled* nil
  "Whether transaction relay is enabled on mainnet. Default NIL for safety.")

(defvar *max-inbound-connections* 114
  "Inbound connections we keep (excess are disconnected at merge time). Set by
start-node via automatic-inbound-capacity; the default is Core's 125 - 11.")

(defvar *max-automatic-connections* 125
  "Core -maxconnections / CConnman::m_max_automatic_connections (net.h:1078):
the automatic connection TOTAL, outbound plus inbound. Set by start-node from
-maxconnections; the default is Core's DEFAULT_MAX_PEER_CONNECTIONS.

Kept beside the two figures derived from it — the outbound target is
NODE-MAX-PEERS and the inbound capacity *MAX-INBOUND-CONNECTIONS* — because
Core's addrman failure-counting gate reads the TOTAL and neither derived
number can be turned back into it (net.cpp:2888, `std::min(
m_max_automatic_connections - 1, 2)').")

(defconstant +node-exit-clean+ 0
  "Process exit code for a deliberate, completed stop (`stop` RPC, SIGTERM,
-stopatheight). The supervisor must NOT respawn on this.")
(defconstant +node-exit-error+ 1
  "Process exit code for a deterministic failure (bad config, unrecoverable
chainstate, disk space): respawning immediately just spins on it.")
(defconstant +node-exit-watchdog+ 7
  "Process exit code when the node stopped running without being asked to
(fatal snapshot, crashed sync thread): the supervisor should respawn.")

(defun make-genesis-header (network)
  "Construct the genesis block header for NETWORK, taken from the full
genesis-block construction (bl.store:make-genesis-block) so the
merkle root is COMPUTED from the real per-network coinbase and the header
hash is verified against the known genesis hash. A previous version shared
mainnet's merkle-root constant across all networks, which was wrong for
testnet4 (its genesis coinbase differs; Core kernel/chainparams.cpp:367-379)."
  (bl.ser:bitcoin-block-header
   (bl.store:make-genesis-block network)))

;;;; The signet chain, INSTANTIATED from its options
;;;;
;;;; Core does not keep signet in a table: SigNetParams is a constructor over
;;;; SigNetOptions (kernel/chainparams.cpp:437-511), fed by ReadSigNetArgs
;;;; (chainparams.cpp:26-40) from -signetchallenge and -signetseednode. The
;;;; challenge is the SEED of the whole chain identity, not one more consensus
;;;; constant beside the others, so a custom signet is a separate p2p network
;;;; with its own message start, its own seeds and no inherited chain-work
;;;; floor. Our :signet row is that constructor's DEFAULT construction; these
;;;; two functions are the constructor.

(defun signet-message-start (challenge)
  "The message start (pchMessageStart) of the signet whose block challenge is
CHALLENGE -- the first four bytes of sha256d over the SERIALIZED challenge
(Core kernel/chainparams.cpp:507-511: `HashWriter h{}; h << consensus.signet_challenge`).

The challenge is a byte VECTOR, so `<<` writes a CompactSize length prefix and
then the bytes; hashing the bare script instead yields a different magic and a
node that no Core peer on the same signet will handshake with. The default
public signet challenge must come back as 0A03CF40 -- that is the positive
control the tests keep on this derivation."
  (let ((buf (bl.bytes:make-byte-buf)))
    (bl.bytes:bb-write-var-bytes buf challenge)
    (subseq (bl.crypto:hash256 (bl.bytes:bb-finish buf)) 0 4)))

(defun signet-chain-params (&key challenge seeds)
  "The chain-params for THIS run's signet (Core SigNetParams(SigNetOptions)).

CHALLENGE is the -signetchallenge script as bytes, or NIL for the public
signet; SEEDS is the -signetseednode list, which REPLACES the DNS seeds
whether or not a challenge was given (kernel/chainparams.cpp:471-473).

With a custom challenge Core clears the seeds, zeroes nMinimumChainWork and
zeroes defaultAssumeValid (:458-465) -- the public signet's accumulated work is
a floor a fresh private signet can never cross, so inheriting it leaves the node
permanently in IBD. It does NOT re-derive the genesis block (CreateGenesisBlock
takes fixed arguments at :514) and it does NOT clear m_assumeutxo_data, which is
assigned unconditionally at :520-533; both are kept here for the same reason.
An explicit -minimumchainwork / -assumevalid still wins over the zeroes, because
those are applied as overrides at their own use sites, which is Core's ordering
too (ApplyArgsManOptions runs after CreateChainParams)."
  (let ((params (bl.chain:copy-chain-params
                 (bl.chain:chain-params-template :signet))))
    (when challenge
      (setf (bl.chain:chain-params-magic params) (signet-message-start challenge)
            (bl.chain:chain-params-minimum-chain-work params) 0
            (bl.chain:chain-params-assumevalid-hex params) nil
            (bl.chain:chain-params-dns-seeds params) '()
            (bl.chain:chain-params-fixed-seeds params) '()))
    (when seeds
      (setf (bl.chain:chain-params-dns-seeds params) (copy-list seeds)))
    params))
