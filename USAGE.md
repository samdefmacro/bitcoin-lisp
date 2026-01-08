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

# On Ubuntu/Debian (see detailed instructions below)
sudo apt-get install sbcl libsecp256k1-dev
```

## Ubuntu/Linux Setup

### Step 1: Install SBCL

```bash
# Update package list
sudo apt update

# Install SBCL
sudo apt install sbcl
```

Verify installation:
```bash
sbcl --version
# Should output something like: SBCL 2.3.0
```

### Step 2: Install libsecp256k1

```bash
# Install the development library
sudo apt install libsecp256k1-dev

# Verify the library is installed
ldconfig -p | grep secp256k1
# Should output: libsecp256k1.so.2 (or similar)
```

### Step 3: Install Quicklisp

Quicklisp is the package manager for Common Lisp:

```bash
# Check if Quicklisp is already installed
ls ~/quicklisp/setup.lisp 2>/dev/null && echo "Quicklisp already installed!"
```

**If not installed:**
```bash
# Download Quicklisp installer
curl -O https://beta.quicklisp.org/quicklisp.lisp

# Install Quicklisp
sbcl --load quicklisp.lisp \
     --eval '(quicklisp-quickstart:install)' \
     --eval '(ql:add-to-init-file)' \
     --quit
```

**If already installed**, just ensure it loads on SBCL startup:
```bash
sbcl --eval '(load "~/quicklisp/setup.lisp")' \
     --eval '(ql:add-to-init-file)' \
     --quit
```

This installs Quicklisp to `~/quicklisp/` and configures SBCL to load it on startup.

### Step 4: Clone and Load bitcoin-lisp

```bash
# Clone the repository to Quicklisp's local-projects
cd ~/quicklisp/local-projects
git clone <repository-url> bitcoin-lisp

# Or create a symlink if you have it elsewhere
ln -s /path/to/bitcoin-lisp ~/quicklisp/local-projects/bitcoin-lisp
```

Now start SBCL and load the system:

```bash
sbcl
```

```lisp
;; Load dependencies and the system
(ql:quickload "bitcoin-lisp")

;; Start the node
(bitcoin-lisp:start-node)

;; Check status
(bitcoin-lisp:node-status)
```

### Step 5: Running as a Background Service (Optional)

Create a systemd service file for running the node:

```bash
sudo nano /etc/systemd/system/bitcoin-lisp.service
```

```ini
[Unit]
Description=Bitcoin-Lisp Node
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/quicklisp/local-projects/bitcoin-lisp
ExecStart=/usr/bin/sbcl --load /home/YOUR_USERNAME/quicklisp/setup.lisp \
    --eval '(ql:quickload "bitcoin-lisp")' \
    --eval '(bitcoin-lisp:start-node :sync t)' \
    --eval '(loop (sleep 3600))'
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable bitcoin-lisp
sudo systemctl start bitcoin-lisp

# Check status
sudo systemctl status bitcoin-lisp
```

### Ubuntu Troubleshooting

#### libsecp256k1 not found

If you get an error about libsecp256k1 not being found:

```bash
# Check if library is installed
dpkg -l | grep secp256k1

# Check library path
find /usr -name "libsecp256k1*" 2>/dev/null

# If library exists but not found, update library cache
sudo ldconfig
```

#### SBCL memory issues

For large blockchain sync, you may need to increase SBCL's heap size:

```bash
sbcl --dynamic-space-size 4096  # 4GB heap
```

#### DNS resolution fails

If peer discovery fails, check your network:

```bash
# Test DNS resolution
nslookup seed.testnet.bitcoin.sprovoost.nl

# Check firewall isn't blocking outbound connections
sudo ufw status
```

## macOS Setup

### Using Homebrew

```bash
# Install SBCL
brew install sbcl

# Install libsecp256k1
brew install secp256k1
```

### Install Quicklisp

```bash
curl -O https://beta.quicklisp.org/quicklisp.lisp
sbcl --load quicklisp.lisp \
     --eval '(quicklisp-quickstart:install)' \
     --eval '(ql:add-to-init-file)' \
     --quit
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
- On Ubuntu, check firewall: `sudo ufw status`

### Slow synchronization
- Bitcoin blockchain sync takes time, especially on testnet
- Consider running with `:max-peers 8` for more connections
- Increase heap size: `sbcl --dynamic-space-size 4096`

### libsecp256k1 not found

**On Ubuntu/Debian:**
```bash
sudo apt install libsecp256k1-dev
sudo ldconfig
```

**On macOS:**
```bash
brew install secp256k1
```

If still not found, check the library path:
```lisp
;; In SBCL, check where CFFI is looking
(cffi:foreign-library-pathname 'bitcoin-lisp.crypto::libsecp256k1)
```

### SBCL crashes with memory errors
Increase the dynamic space size:
```bash
sbcl --dynamic-space-size 8192  # 8GB heap
```

### Quicklisp can't find bitcoin-lisp
Ensure the project is in Quicklisp's local-projects:
```bash
ls ~/quicklisp/local-projects/bitcoin-lisp/
# Should show bitcoin-lisp.asd
```

Or register it manually in SBCL:
```lisp
(push #P"/path/to/bitcoin-lisp/" asdf:*central-registry*)
(asdf:load-system "bitcoin-lisp")
```

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


