## MODIFIED Requirements

### Requirement: Persistence and Recovery
The system SHALL persist state to disk and recover on restart.

Persisted state includes:
- Best block hash and height
- UTXO set (all entries serialized to binary file)
- Block index entries (header chain with metadata)

#### Scenario: Graceful shutdown
- **WHEN** the node is shutting down
- **THEN** the UTXO set, header index, and chain state are flushed to disk

#### Scenario: Startup recovery
- **WHEN** the node starts
- **THEN** the UTXO set, header index, and chain state are loaded from disk and the node resumes from the last persisted state

#### Scenario: Periodic flush during sync
- **GIVEN** blocks are being downloaded and connected
- **WHEN** 1000 blocks have been connected since the last flush
- **THEN** the UTXO set and chain state are flushed to disk

#### Scenario: Resume sync after restart
- **GIVEN** the node was stopped during sync at height N
- **WHEN** the node restarts
- **THEN** sync resumes from height N without re-downloading blocks 0 through N

## ADDED Requirements

### Requirement: UTXO Set Persistence
The system SHALL serialize and deserialize the UTXO set to and from disk.

Each UTXO entry is serialized as:
- 36-byte key (32-byte txid + 4-byte output index)
- 8-byte value (satoshis)
- 4-byte height
- 1-byte coinbase flag
- 4-byte script length
- Variable-length script-pubkey bytes

#### Scenario: Save UTXO set to disk
- **GIVEN** a UTXO set with entries
- **WHEN** saving to disk
- **THEN** all entries are written to a binary file

#### Scenario: Load UTXO set from disk
- **GIVEN** a previously saved UTXO set file
- **WHEN** loading on startup
- **THEN** all entries are restored with correct values, heights, and scripts

#### Scenario: Round-trip consistency
- **GIVEN** a UTXO set saved to disk
- **WHEN** loading and comparing to the original
- **THEN** the loaded set has identical entries to the original

### Requirement: Header Index Persistence
The system SHALL serialize and deserialize the block index to and from disk.

Each block-index-entry is serialized as:
- 32-byte block hash
- 4-byte height
- 80-byte header data
- 32-byte chainwork (big integer serialized)
- 1-byte validation status
- 32-byte previous block hash (for chain reconstruction)

#### Scenario: Save header index to disk
- **GIVEN** a block index with entries
- **WHEN** saving to disk
- **THEN** all entries are written to a binary file

#### Scenario: Load header index from disk
- **GIVEN** a previously saved header index file
- **WHEN** loading on startup
- **THEN** all entries are restored with correct chain linkage

#### Scenario: Incremental append
- **GIVEN** a new block is connected
- **WHEN** the header index is updated
- **THEN** only the new entry is appended (not the entire index rewritten)
