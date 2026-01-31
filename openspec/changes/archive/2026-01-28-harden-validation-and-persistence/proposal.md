# Change: Harden validation and persistence for testnet reliability

## Why
The node has solid foundations (script engine, IBD, mempool, peer management) but several gaps reduce reliability during real testnet sync and operation:
- `validate-block` does not validate transaction scripts at all -- it checks structure and UTXO context but skips script execution entirely, meaning invalid signatures are accepted during block connection
- Persistence files (UTXO set, header index) have no checksums to detect corruption
- The UTXO set save uses direct file writes with no atomic rename, so an interrupted save corrupts the file
- Peers that send invalid blocks or transactions are disconnected but never banned, so they can reconnect immediately
- No witness commitment validation (BIP 141) when connecting blocks with witness data
- No BIP 34 coinbase height validation

## What Changes
- **Block script validation**: Add script validation to the block connection path by calling the Coalton interop script execution engine from `validate-block`, so transaction signatures are actually checked during IBD and block connection
- **Witness commitment validation**: Validate the witness merkle root in the coinbase output when connecting SegWit blocks (BIP 141 commitment structure)
- **Persistence integrity**: Add CRC32 checksums to UTXO set and header index files; add atomic write-rename for UTXO set saves; validate checksums on load
- **Peer misbehavior banning**: Add misbehavior scoring to the existing peer health infrastructure; ban peers that send invalid blocks/headers/transactions using the existing `:banned` peer state
- **BIP 34 coinbase height**: Validate that the coinbase scriptSig encodes the block height (required since block 227,931 on mainnet, block 21,111 on testnet)
- **Persistence corruption tests**: Add tests for truncated files, invalid checksums, partial writes, and recovery
- **Reorg edge-case tests**: Add tests for multi-block reorgs, reorg with missing undo data, and persistence consistency after reorg

## Impact
- Affected specs: `validation`, `storage`, `networking`
- Affected code:
  - `src/validation/block.lisp` (script validation call, witness commitment, BIP 34)
  - `src/validation/transaction.lisp` (wire script validation to Coalton interop)
  - `src/storage/utxo.lisp` (atomic writes, checksums)
  - `src/storage/chain.lisp` (checksums)
  - `src/networking/peer.lisp` (misbehavior scoring, ban list)
  - `src/networking/protocol.lisp` (misbehavior reporting on invalid data)
  - `tests/persistence-tests.lisp` (corruption/recovery tests)
  - `tests/validation-tests.lisp` (reorg edge cases, BIP 34, witness commitment)
