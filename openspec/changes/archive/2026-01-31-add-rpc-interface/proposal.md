# Change: Add RPC Interface

## Why
The node currently has no external interface for querying blockchain state, retrieving blocks, or inspecting the mempool. An RPC interface is essential for debugging, monitoring, and integration with external tools like block explorers, wallets, and testing frameworks.

## What Changes
- New `rpc` capability: JSON-RPC 2.0 server over HTTP with Bitcoin Core-compatible methods
- Modified `node` module: Start/stop RPC server alongside node lifecycle

## Impact
- Affected specs: `rpc` (new)
- Affected code: `src/rpc/` (new directory), `src/node.lisp` (modified)
- No breaking changes to existing functionality
- New dependency: HTTP server library (hunchentoot or clack)
