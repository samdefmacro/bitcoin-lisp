(in-package #:bitcoin-lisp)

#+sbcl
(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-sprof))

;;;; The node (Core init.cpp / bitcoind.cpp), one file per concern, loaded in
;;;; this order: params, state, notify, datadir, rpc-config, logging, entropy,
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

(defun network-port (network)
  "NETWORK's default P2P port (chain-params-port)."
  (bl.chain:chain-params-port (bl.chain:find-chain-params network)))

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

(defun network-dns-seeds (network)
  "NETWORK's DNS seeds (chain-params-dns-seeds)."
  (bl.chain:chain-params-dns-seeds (bl.chain:find-chain-params network)))

(defun network-rpc-port (network)
  "NETWORK's default RPC port (chain-params-rpc-port)."
  (bl.chain:chain-params-rpc-port (bl.chain:find-chain-params network)))

(defvar *mainnet-relay-enabled* nil
  "Whether transaction relay is enabled on mainnet. Default NIL for safety.")

(defvar *max-inbound-connections* 114
  "Inbound connections we keep (excess are disconnected at merge time). Set by
start-node via automatic-inbound-capacity; the default is Core's 125 - 11.")

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
