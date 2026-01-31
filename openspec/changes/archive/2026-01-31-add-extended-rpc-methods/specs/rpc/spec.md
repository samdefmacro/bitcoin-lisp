# rpc Specification Delta

## ADDED Requirements

### Requirement: Raw Transaction Query Methods
The system SHALL provide methods to fetch and decode raw transactions.

Methods:
- `getrawtransaction <txid> [verbose]`: Returns raw transaction data
- `decoderawtransaction <hex>`: Decodes hex transaction to JSON

For `getrawtransaction`:
- If `verbose=false` (default), returns hex-encoded transaction
- If `verbose=true`, returns JSON with transaction details
- Searches mempool for unconfirmed transactions
- Returns error if transaction not found in mempool (blockchain lookup requires transaction index, not implemented in Phase 1)

For `decoderawtransaction`:
- Parses hex string as serialized transaction
- Returns JSON with version, inputs, outputs, locktime
- Does not require transaction to exist in chain

#### Scenario: getrawtransaction from mempool
- **GIVEN** transaction T is in the mempool
- **WHEN** getrawtransaction(T.txid, false) is called
- **THEN** response is hex-encoded transaction bytes

#### Scenario: getrawtransaction verbose
- **GIVEN** transaction T is in the mempool
- **WHEN** getrawtransaction(T.txid, true) is called
- **THEN** response is JSON with txid, version, vin, vout, locktime

#### Scenario: getrawtransaction not found
- **GIVEN** txid T does not exist in mempool
- **WHEN** getrawtransaction(T) is called
- **THEN** error code -5 is returned indicating transaction not found

#### Scenario: decoderawtransaction valid
- **GIVEN** valid hex-encoded transaction H
- **WHEN** decoderawtransaction(H) is called
- **THEN** response is JSON with parsed transaction fields

#### Scenario: decoderawtransaction invalid hex
- **GIVEN** invalid hex string H (odd length or non-hex chars)
- **WHEN** decoderawtransaction(H) is called
- **THEN** error code -22 (Invalid hex) is returned

#### Scenario: decoderawtransaction malformed tx
- **GIVEN** valid hex that doesn't parse as transaction
- **WHEN** decoderawtransaction(H) is called
- **THEN** error code -22 is returned indicating decode failure

### Requirement: Raw Transaction Construction
The system SHALL provide a method to construct unsigned transactions.

Method:
- `createrawtransaction <inputs> <outputs> [locktime]`

Parameters:
- `inputs`: Array of `{"txid": "hex", "vout": n, "sequence": n}` (sequence optional, defaults to 0xffffffff)
- `outputs`: Object `{"address": amount, ...}` where amount is in BTC
- `locktime`: Optional transaction locktime (default 0)

Returns hex-encoded unsigned transaction with empty scriptSigs.

Supported address formats for outputs:
- Base58Check: P2PKH (m.../n... testnet), P2SH (2... testnet)
- Bech32: P2WPKH, P2WSH (tb1q... testnet)
- Bech32m: P2TR (tb1p... testnet)

#### Scenario: createrawtransaction basic
- **GIVEN** valid input references and output addresses
- **WHEN** createrawtransaction is called
- **THEN** response is hex transaction with specified inputs/outputs

#### Scenario: createrawtransaction with locktime
- **GIVEN** inputs, outputs, and locktime 500000
- **WHEN** createrawtransaction is called with locktime
- **THEN** response transaction has locktime 500000

#### Scenario: createrawtransaction invalid input txid
- **GIVEN** input with invalid txid format
- **WHEN** createrawtransaction is called
- **THEN** error code -8 (Invalid parameter) is returned

#### Scenario: createrawtransaction invalid address
- **GIVEN** output with invalid or unrecognized address
- **WHEN** createrawtransaction is called
- **THEN** error code -5 (Invalid address) is returned

#### Scenario: createrawtransaction wrong network address
- **GIVEN** output with mainnet address on testnet node
- **WHEN** createrawtransaction is called
- **THEN** error code -5 (Invalid address) is returned

#### Scenario: createrawtransaction negative amount
- **GIVEN** output with negative amount
- **WHEN** createrawtransaction is called
- **THEN** error code -3 (Invalid amount) is returned

#### Scenario: createrawtransaction amount too large
- **GIVEN** output with amount > 21 million BTC
- **WHEN** createrawtransaction is called
- **THEN** error code -3 (Invalid amount) is returned

### Requirement: Fee Estimation
The system SHALL provide a method to estimate transaction fees.

Method:
- `estimatesmartfee <conf_target> [estimate_mode]`

Parameters:
- `conf_target`: Number of blocks for confirmation target (1-1008)
- `estimate_mode`: Optional, ignored (for API compatibility)

Returns:
- `feerate`: Estimated fee rate in BTC/kvB (1000 virtual bytes)
- `blocks`: The conf_target value

Implementation note: Phase 1 returns a conservative fixed estimate. Proper fee estimation based on historical block data is deferred to Phase 2.

#### Scenario: estimatesmartfee normal
- **GIVEN** node has completed initial block download
- **WHEN** estimatesmartfee(6) is called
- **THEN** response includes feerate (positive number) and blocks=6

#### Scenario: estimatesmartfee during IBD
- **GIVEN** node is still performing initial block download
- **WHEN** estimatesmartfee is called
- **THEN** error is returned indicating insufficient data

#### Scenario: estimatesmartfee invalid target zero
- **GIVEN** conf_target is 0
- **WHEN** estimatesmartfee is called
- **THEN** error code -8 (Invalid parameter) is returned

#### Scenario: estimatesmartfee invalid target negative
- **GIVEN** conf_target is negative
- **WHEN** estimatesmartfee is called
- **THEN** error code -8 (Invalid parameter) is returned

#### Scenario: estimatesmartfee target too high
- **GIVEN** conf_target is > 1008
- **WHEN** estimatesmartfee is called
- **THEN** error code -8 (Invalid parameter) is returned

### Requirement: Address Validation
The system SHALL provide a method to validate Bitcoin addresses.

Method:
- `validateaddress <address>`

Returns object with:
- `isvalid`: Boolean indicating validity
- `address`: The address (if valid)
- `scriptPubKey`: Hex scriptPubKey (if valid)
- `isscript`: True for P2SH/P2WSH
- `iswitness`: True for SegWit addresses
- `witness_version`: 0 or 1 for SegWit (if applicable)
- `witness_program`: Hex witness program (if applicable)

Supported formats:
- Base58Check: P2PKH (testnet prefix 0x6f → m.../n...), P2SH (testnet prefix 0xc4 → 2...)
- Bech32: P2WPKH (20-byte program), P2WSH (32-byte program) - tb1q...
- Bech32m: P2TR (32-byte program) - tb1p...

#### Scenario: validateaddress P2PKH
- **GIVEN** valid testnet P2PKH address (m... or n...)
- **WHEN** validateaddress is called
- **THEN** isvalid=true, iswitness=false, isscript=false, scriptPubKey is OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG

#### Scenario: validateaddress P2SH
- **GIVEN** valid testnet P2SH address (2...)
- **WHEN** validateaddress is called
- **THEN** isvalid=true, iswitness=false, isscript=true, scriptPubKey is OP_HASH160 <hash> OP_EQUAL

#### Scenario: validateaddress P2WPKH
- **GIVEN** valid testnet P2WPKH address (tb1q... with 20-byte program)
- **WHEN** validateaddress is called
- **THEN** isvalid=true, iswitness=true, witness_version=0, witness_program is 20 bytes

#### Scenario: validateaddress P2WSH
- **GIVEN** valid testnet P2WSH address (tb1q... with 32-byte program)
- **WHEN** validateaddress is called
- **THEN** isvalid=true, iswitness=true, witness_version=0, witness_program is 32 bytes

#### Scenario: validateaddress P2TR
- **GIVEN** valid testnet P2TR address (tb1p...)
- **WHEN** validateaddress is called
- **THEN** isvalid=true, iswitness=true, witness_version=1, witness_program is 32 bytes

#### Scenario: validateaddress invalid checksum
- **GIVEN** Base58 address with invalid checksum
- **WHEN** validateaddress is called
- **THEN** isvalid=false

#### Scenario: validateaddress invalid bech32
- **GIVEN** malformed bech32 address
- **WHEN** validateaddress is called
- **THEN** isvalid=false

#### Scenario: validateaddress wrong network
- **GIVEN** mainnet address (1... or bc1...) on testnet node
- **WHEN** validateaddress is called
- **THEN** isvalid=false

#### Scenario: validateaddress empty string
- **GIVEN** empty string as address
- **WHEN** validateaddress is called
- **THEN** isvalid=false

### Requirement: Script Decoding
The system SHALL provide a method to decode Bitcoin scripts.

Method:
- `decodescript <hex>`

Returns:
- `asm`: Script disassembly (opcode names and hex data pushes)
- `type`: Detected script type (pubkeyhash, scripthash, witness_v0_keyhash, witness_v0_scripthash, witness_v1_taproot, multisig, nulldata, nonstandard)
- `reqSigs`: Required signatures (for multisig)
- `addresses`: Array of addresses (if applicable)
- `p2sh`: P2SH address wrapping this script
- `segwit`: Nested SegWit address (if script is witness program)

#### Scenario: decodescript P2PKH
- **GIVEN** hex P2PKH script (OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG)
- **WHEN** decodescript is called
- **THEN** type="pubkeyhash", asm shows opcodes, addresses contains P2PKH address

#### Scenario: decodescript P2SH
- **GIVEN** hex P2SH script (OP_HASH160 <20-byte-hash> OP_EQUAL)
- **WHEN** decodescript is called
- **THEN** type="scripthash", addresses contains P2SH address

#### Scenario: decodescript P2WPKH
- **GIVEN** hex witness v0 keyhash script (OP_0 <20-byte-hash>)
- **WHEN** decodescript is called
- **THEN** type="witness_v0_keyhash", segwit contains tb1q address

#### Scenario: decodescript P2WSH
- **GIVEN** hex witness v0 scripthash script (OP_0 <32-byte-hash>)
- **WHEN** decodescript is called
- **THEN** type="witness_v0_scripthash", segwit contains tb1q address

#### Scenario: decodescript P2TR
- **GIVEN** hex witness v1 script (OP_1 <32-byte-key>)
- **WHEN** decodescript is called
- **THEN** type="witness_v1_taproot", segwit contains tb1p address

#### Scenario: decodescript multisig
- **GIVEN** hex bare multisig script (OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG)
- **WHEN** decodescript is called
- **THEN** type="multisig", reqSigs=2, asm shows M-of-N structure

#### Scenario: decodescript nulldata
- **GIVEN** hex OP_RETURN script (OP_RETURN <data>)
- **WHEN** decodescript is called
- **THEN** type="nulldata", asm shows OP_RETURN and data

#### Scenario: decodescript invalid hex
- **GIVEN** invalid hex string (odd length or non-hex)
- **WHEN** decodescript is called
- **THEN** error code -22 (Invalid hex) is returned

#### Scenario: decodescript empty
- **GIVEN** empty script (zero bytes, hex "")
- **WHEN** decodescript is called
- **THEN** type="nonstandard", asm=""

#### Scenario: decodescript nonstandard
- **GIVEN** script that doesn't match any standard pattern
- **WHEN** decodescript is called
- **THEN** type="nonstandard", asm shows opcodes/data
