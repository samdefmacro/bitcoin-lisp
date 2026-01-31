## ADDED Requirements

### Requirement: UTXO Set Persistence
The system SHALL persist the UTXO set to disk and reload it on startup.

The persistence format SHALL include integrity protection:
- 4-byte magic identifier ("UTXO")
- 4-byte format version
- 4-byte entry count
- Entry data (key + value per entry)
- 4-byte CRC32 checksum of all preceding bytes

UTXO set writes SHALL be atomic: data is written to a temporary file (`<path>.tmp`), then renamed to the final path. This prevents corruption from interrupted writes.

On load, the system SHALL verify magic bytes, format version, and CRC32 checksum before accepting the data. If verification fails, the file is rejected and the node starts with an empty UTXO set.

If a `.tmp` file exists but the main file does not, the system SHALL log a warning (indicates an interrupted write) and start with an empty UTXO set.

Old-format files (no magic bytes) SHALL be detected and loaded using the legacy parser for backward compatibility. The new format is written on the next save.

#### Scenario: Save and reload UTXO set
- **GIVEN** a UTXO set with entries
- **WHEN** saving to disk and reloading
- **THEN** all entries are preserved with identical values

#### Scenario: Detect truncated UTXO file
- **GIVEN** a UTXO file that was truncated mid-write
- **WHEN** loading the file
- **THEN** the CRC32 check fails and the file is rejected

#### Scenario: Detect corrupted UTXO file
- **GIVEN** a UTXO file with flipped bits in an entry
- **WHEN** loading the file
- **THEN** the CRC32 check fails and the file is rejected

#### Scenario: Atomic write prevents corruption
- **GIVEN** a valid UTXO file on disk
- **WHEN** a save operation is interrupted (simulated by leaving `.tmp` file)
- **THEN** the original file remains intact and loadable

#### Scenario: Reject unknown format version
- **GIVEN** a UTXO file with format version 99
- **WHEN** loading the file
- **THEN** the file is rejected with a version mismatch warning

#### Scenario: Backward compatibility with old format
- **GIVEN** a UTXO file in the old format (no magic bytes, no checksum)
- **WHEN** loading the file
- **THEN** the old format is detected and loaded successfully

### Requirement: Header Index Persistence
The system SHALL persist the header chain index to disk with checksum integrity protection.

The format SHALL include:
- 4-byte magic identifier ("HIDX")
- 4-byte format version
- 4-byte entry count
- Entry data
- 4-byte CRC32 checksum

The header index already uses a two-phase write pattern (placeholder count, then entries, then count update). This existing pattern is retained; CRC32 and magic bytes are added.

#### Scenario: Save and reload header index
- **GIVEN** a header index with block entries
- **WHEN** saving to disk and reloading
- **THEN** all entries are preserved and the chain can resume sync

#### Scenario: Detect corrupted header index
- **GIVEN** a header index file with corrupted data
- **WHEN** loading the file
- **THEN** the CRC32 check fails and the file is rejected

### Requirement: Persistence Consistency After Reorg
The system SHALL maintain UTXO set consistency through chain reorganizations and persistence cycles.

After a reorg followed by a save/load cycle, the UTXO set SHALL reflect the current chain tip accurately.

#### Scenario: UTXO consistency after reorg and reload
- **GIVEN** a reorg has occurred and the UTXO set has been updated
- **WHEN** the UTXO set is saved and reloaded
- **THEN** the reloaded set matches the post-reorg state exactly
