# Change: Add Segregated Witness (SegWit) Support

## Why

The current script interpreter passes all 1190 Bitcoin Core tests except 23 WITNESS tests. SegWit (BIP 141/143/144) is essential for modern Bitcoin transactions, enabling P2WPKH, P2WSH, and nested P2SH-P2WPKH scripts. Without SegWit support, the interpreter cannot validate ~40% of current Bitcoin transactions.

## What Changes

- **MODIFIED** `script` capability: Add witness program validation and BIP 143 sighash
- **NEW** witness version handling (v0 for current SegWit, extensible for future versions)

Key additions:
- Witness program detection and validation
- BIP 143 signature hashing algorithm (different from legacy sighash)
- P2WPKH (Pay-to-Witness-Public-Key-Hash) validation
- P2WSH (Pay-to-Witness-Script-Hash) validation
- P2SH-P2WPKH and P2SH-P2WSH nested scripts
- Witness stack processing

## Impact

- Affected specs: `script` (modified)
- Affected code: `src/coalton/script.lisp`, `src/coalton/interop.lisp`, `tests/bitcoin-core-script-tests.lisp`
- Dependencies: Requires completed `script` spec (typed script operations)

## Scope

This proposal covers:
- Native SegWit v0: P2WPKH (20-byte program) and P2WSH (32-byte program)
- Nested SegWit: P2SH-P2WPKH and P2SH-P2WSH
- BIP 143 signature hash algorithm
- Witness program version validation
- WITNESS flag handling in test runner

Out of scope:
- Taproot/Tapscript (SegWit v1, BIP 340-342) - future proposal
- Witness transaction serialization (already handled by serialization spec)

## Technical Background

### Witness Programs

A witness program is identified by:
1. scriptPubKey length: 4-42 bytes
2. First byte: version (0x00 for v0)
3. Second byte: push opcode for program (0x14 for 20 bytes, 0x20 for 32 bytes)
4. Remaining bytes: the program hash

### P2WPKH (BIP 141)
- scriptPubKey: `OP_0 <20-byte-key-hash>`
- Witness: `<signature> <pubkey>`
- Implicit script: `DUP HASH160 <20-byte-key-hash> EQUALVERIFY CHECKSIG`

### P2WSH (BIP 141)
- scriptPubKey: `OP_0 <32-byte-script-hash>`
- Witness: `<args...> <witness-script>`
- Script hash must match SHA256(witness-script)

### BIP 143 Sighash

SegWit uses a different signature hash algorithm that:
- Prevents quadratic hashing attacks
- Commits to input values (amounts)
- Has different serialization order
