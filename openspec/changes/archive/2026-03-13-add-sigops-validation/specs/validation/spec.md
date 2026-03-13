## ADDED Requirements

### Requirement: Signature Operations Cost Validation
The system SHALL validate that the total signature operations cost of a block does not exceed 80,000 (BIP 141 weighted limit).

Sigops cost is calculated per transaction as the sum of:
- Legacy sigops (from scriptSig and scriptPubKey of all inputs/outputs) multiplied by the witness scale factor (4)
- P2SH sigops (from the redeemScript of P2SH inputs) multiplied by the witness scale factor (4)
- Witness sigops at face value (1): P2WPKH counts as 1, P2WSH counts sigops from the witness script (last item in witness stack). Both native and P2SH-wrapped witness programs are handled.

Legacy and P2SH counting uses these rules:
- OP_CHECKSIG (0xac) and OP_CHECKSIGVERIFY (0xad): 1 sigop each
- OP_CHECKMULTISIG (0xae) and OP_CHECKMULTISIGVERIFY (0xaf): For legacy (inaccurate) counting, always 20. For P2SH/witness (accurate) counting, use the preceding small-integer opcode (OP_1..OP_16) as the key count.

Block sigops cost is the sum of all transaction sigops costs. The block is rejected if this exceeds 80,000.

#### Scenario: Accept block at sigops cost limit
- **GIVEN** a block with total sigops cost of 80,000
- **WHEN** validating the block
- **THEN** sigops validation passes

#### Scenario: Reject block exceeding sigops cost limit
- **GIVEN** a block with total sigops cost of 80,004
- **WHEN** validating the block
- **THEN** validation fails with :too-many-sigops error

#### Scenario: Legacy P2PKH sigops cost
- **GIVEN** a legacy P2PKH transaction (1 OP_CHECKSIG in scriptPubKey)
- **WHEN** calculating its sigops cost
- **THEN** the cost is 4 (1 sigop * witness scale factor 4)

#### Scenario: Witness P2WPKH sigops cost
- **GIVEN** a native P2WPKH transaction
- **WHEN** calculating its sigops cost
- **THEN** the cost is 1 (1 witness sigop * 1)

#### Scenario: P2SH-wrapped P2WPKH sigops cost
- **GIVEN** a P2SH-P2WPKH transaction
- **WHEN** calculating its sigops cost
- **THEN** the cost is 1 (1 witness sigop * 1)

#### Scenario: Bare multisig inaccurate count
- **GIVEN** a transaction spending a 2-of-3 bare multisig output
- **WHEN** counting legacy sigops (inaccurate)
- **THEN** OP_CHECKMULTISIG counts as 20 (not 3)

#### Scenario: P2SH multisig accurate count
- **GIVEN** a transaction spending a P2SH 2-of-3 multisig
- **WHEN** counting P2SH sigops (accurate)
- **THEN** OP_CHECKMULTISIG counts as 3 (the n from preceding OP_3)
