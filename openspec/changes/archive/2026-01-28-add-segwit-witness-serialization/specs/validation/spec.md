## MODIFIED Requirements

### Requirement: Script Validation
The system SHALL execute Bitcoin scripts to validate transaction authorization, including witness programs.

The script interpreter SHALL support:
- Stack operations (OP_DUP, OP_DROP, OP_SWAP, etc.)
- Crypto operations (OP_HASH160, OP_HASH256, OP_CHECKSIG, etc.)
- Flow control (OP_IF, OP_ELSE, OP_ENDIF, OP_VERIFY)
- Arithmetic operations (OP_ADD, OP_SUB, OP_EQUAL, etc.)
- Witness program validation (P2WPKH, P2WSH, P2TR) using deserialized witness stacks

For witness program inputs, the system SHALL pass the witness stack from the transaction's serialized witness data to the Coalton `validate-witness-program` function.

#### Scenario: Validate P2PKH transaction
- **GIVEN** a transaction spending a P2PKH output with valid signature
- **WHEN** executing scriptSig + scriptPubKey
- **THEN** the script succeeds and validation passes

#### Scenario: Reject invalid signature
- **GIVEN** a transaction with an invalid ECDSA signature
- **WHEN** executing OP_CHECKSIG
- **THEN** the script fails and validation rejects the transaction

#### Scenario: Validate P2WPKH witness input
- **GIVEN** a transaction spending a P2WPKH output with witness data containing a valid signature and public key
- **WHEN** validating the witness program
- **THEN** the witness stack is passed to the Coalton validator and validation succeeds

#### Scenario: Reject witness input with invalid signature
- **GIVEN** a transaction spending a witness program output with an invalid witness stack
- **WHEN** validating the witness program
- **THEN** validation fails with a script error

### Requirement: Block Validation
The system SHALL validate complete blocks against consensus rules, including witness commitment verification.

Checks include:
- First transaction is coinbase, no others are
- Coinbase value doesn't exceed block reward + fees
- All transactions are valid (including witness program validation)
- Merkle root matches transaction hashes
- Block size within limits
- Witness commitment in coinbase matches computed witness merkle root (for blocks with witness data)

The witness merkle root SHALL be computed from wtxids of all transactions (coinbase wtxid = 32 zero bytes). The commitment SHALL be verified against the last OP_RETURN output in the coinbase matching the BIP 141 header (0xaa21a9ed).

#### Scenario: Validate merkle root
- **GIVEN** a block with transactions
- **WHEN** computing the merkle root
- **THEN** it matches the merkle root in the header

#### Scenario: Reject excess coinbase value
- **GIVEN** a block where coinbase output exceeds (subsidy + fees)
- **WHEN** validating the block
- **THEN** validation fails with "coinbase value too high" error

#### Scenario: Validate witness commitment
- **GIVEN** a block with witness transactions and a coinbase containing a witness commitment
- **WHEN** validating the block
- **THEN** the witness merkle root computed from wtxids matches the commitment in the coinbase

#### Scenario: Reject missing witness commitment
- **GIVEN** a block with witness transactions but no witness commitment in the coinbase
- **WHEN** validating the block
- **THEN** validation fails with "missing witness commitment" error
