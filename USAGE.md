# Bitcoin-Lisp Usage Guide

A Bitcoin full node implementation in Common Lisp (SBCL).

## Quick Start

### Prerequisites

1. **SBCL** (Steel Bank Common Lisp) installed
2. **Quicklisp** for package management
3. **libsecp256k1** system library for ECDSA operations

```bash
# On macOS
brew install sbcl
brew install secp256k1

# On Ubuntu/Debian
sudo apt-get install sbcl libsecp256k1-dev
```

### Loading the System

```lisp
;; Load the system via ASDF
(asdf:load-system "bitcoin-lisp")

;; Or use Quicklisp if installed locally
(ql:quickload "bitcoin-lisp")
```

### Running the Node

```lisp
;; Start the node on testnet (default)
(bitcoin-lisp:start-node)

;; Or with custom options
(bitcoin-lisp:start-node
  :data-directory "~/.bitcoin-lisp/"
  :network :testnet
  :log-level :info
  :max-peers 8
  :sync t)

;; Check node status
(bitcoin-lisp:node-status)

;; Stop the node
(bitcoin-lisp:stop-node)
```

## Configuration Options

### Network Selection

```lisp
;; Testnet (default, recommended for development)
(bitcoin-lisp:start-node :network :testnet)

;; Mainnet (real Bitcoin network)
(bitcoin-lisp:start-node :network :mainnet)
```

### Data Directory

The data directory stores blockchain data, chain state, and configuration:

```lisp
(bitcoin-lisp:start-node :data-directory "/path/to/data/")
```

Default: `~/.bitcoin-lisp/`

Directory structure:
```
~/.bitcoin-lisp/
├── blocks/          # Block files (*.blk)
└── chainstate.dat   # Chain state persistence
```

### Log Levels

```lisp
;; Available levels: :debug, :info, :warn, :error
(bitcoin-lisp:start-node :log-level :debug)

;; Redirect logs to a file
(with-open-file (bitcoin-lisp:*log-stream* "/path/to/bitcoin.log"
                  :direction :output
                  :if-exists :append
                  :if-does-not-exist :create)
  (bitcoin-lisp:start-node))
```

### Peer Connections

```lisp
;; Set maximum peer connections
(bitcoin-lisp:start-node :max-peers 4)

;; Start without automatic syncing
(bitcoin-lisp:start-node :sync nil)
```

## Blockchain Synchronization

### Automatic Sync

By default, `start-node` connects to peers and begins syncing:

```lisp
(bitcoin-lisp:start-node :sync t)
```

### Manual Sync

```lisp
;; Start without syncing
(bitcoin-lisp:start-node :sync nil)

;; Manually trigger sync later
(bitcoin-lisp:sync-blockchain bitcoin-lisp:*node* :max-blocks 1000)
```

### Checking Progress

```lisp
;; Print detailed status
(bitcoin-lisp:node-status)

;; Get current height programmatically
(bitcoin-lisp.storage:current-height
  (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*))
```

## Running Tests

```lisp
;; Load the test system
(asdf:load-system "bitcoin-lisp/tests")

;; Run all tests
(bitcoin-lisp.tests:run-tests)

;; Run unit tests only (no network)
(bitcoin-lisp.tests:run-unit-tests)

;; Run integration tests (requires network)
(bitcoin-lisp.tests:run-integration-tests)
```

## API Reference

### Node Functions

| Function | Description |
|----------|-------------|
| `start-node` | Start the Bitcoin node |
| `stop-node` | Stop the running node |
| `node-status` | Print current node status |
| `sync-blockchain` | Manually trigger sync |

### Logging Macros

| Macro | Description |
|-------|-------------|
| `log-debug` | Debug-level log message |
| `log-info` | Info-level log message |
| `log-warn` | Warning-level log message |
| `log-error` | Error-level log message |

### Variables

| Variable | Description |
|----------|-------------|
| `*node*` | Current running node instance |
| `*network*` | Current network (:testnet or :mainnet) |
| `*log-stream*` | Output stream for logs |

## Examples

### Simple Testnet Connection

```lisp
(asdf:load-system "bitcoin-lisp")

;; Start node and sync first 100 blocks
(let ((node (bitcoin-lisp:start-node :sync nil)))
  (bitcoin-lisp:sync-blockchain node :max-blocks 100)
  (bitcoin-lisp:node-status)
  (bitcoin-lisp:stop-node))
```

### Programmatic Block Inspection

```lisp
(asdf:load-system "bitcoin-lisp")
(bitcoin-lisp:start-node :sync nil)

;; Get chain state
(let* ((chain-state (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*))
       (best-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
  (format t "Best block: ~A~%"
          (bitcoin-lisp.crypto:bytes-to-hex best-hash)))

(bitcoin-lisp:stop-node)
```

## Troubleshooting

### No peers found
- Check network connectivity
- DNS seeds may be temporarily unavailable
- Try running with `:log-level :debug` for more info

### Slow synchronization
- Bitcoin blockchain sync takes time, especially on testnet
- Consider running with `:max-peers 8` for more connections

### libsecp256k1 not found
- Ensure the library is installed system-wide
- On macOS: `brew install secp256k1`
- On Linux: `apt-get install libsecp256k1-dev`

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                    Bitcoin-Lisp Node                    │
├────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐ │
│  │ Networking  │  │ Validation  │  │    Storage     │ │
│  │   (P2P)     │◄─┤  (Blocks/   │◄─┤  (Blocks/UTXO) │ │
│  │             │  │    Txs)     │  │                │ │
│  └──────┬──────┘  └──────┬──────┘  └────────────────┘ │
│         │                │                             │
│  ┌──────▼──────────────▼──────┐                       │
│  │       Serialization         │                       │
│  │  (Protocol Data Structures) │                       │
│  └──────────────┬──────────────┘                       │
│                 │                                       │
│  ┌──────────────▼──────────────┐                       │
│  │          Crypto             │                       │
│  │  (SHA256, RIPEMD, secp256k1)│                       │
│  └─────────────────────────────┘                       │
└────────────────────────────────────────────────────────┘
```

## License

MIT License


