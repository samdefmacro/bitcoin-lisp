## ADDED Requirements

### Requirement: ADDRv2 Serialization
The system SHALL serialize and deserialize addrv2 message entries as specified in BIP 155.

Each addrv2 entry SHALL contain:
- Timestamp (4 bytes, uint32 LE)
- Services (compact-size encoded, 1-9 bytes)
- Network ID (1 byte): 1=IPv4, 2=IPv6, 4=TorV3, 5=I2P, 6=CJDNS
- Address length (compact-size encoded)
- Address bytes (variable, up to 512 bytes)
- Port (2 bytes, uint16 big-endian)

The system SHALL validate that address length matches the expected size for known network IDs (IPv4=4, IPv6=16, TorV2=10, TorV3=32, I2P=32, CJDNS=16). Entries with mismatched lengths for known network IDs SHALL be skipped.

Entries with unknown network IDs SHALL be skipped by reading past their bytes without error.

The system SHALL serialize `sendaddrv2` as a message with empty payload.

#### Scenario: Deserialize IPv4 addrv2 entry
- **GIVEN** an addrv2 entry with network ID 1 and 4-byte address
- **WHEN** deserializing the entry
- **THEN** the IPv4 address, port, services, and timestamp are extracted

#### Scenario: Deserialize IPv6 addrv2 entry
- **GIVEN** an addrv2 entry with network ID 2 and 16-byte address
- **WHEN** deserializing the entry
- **THEN** the IPv6 address, port, services, and timestamp are extracted

#### Scenario: Skip unknown network ID
- **GIVEN** an addrv2 entry with an unrecognized network ID
- **WHEN** deserializing the entry
- **THEN** the entry is skipped by reading past its bytes without error

#### Scenario: Skip entry with mismatched address length
- **GIVEN** an addrv2 entry with a known network ID but incorrect address length
- **WHEN** deserializing the entry
- **THEN** the entry is skipped by reading past its bytes without error

#### Scenario: Serialize sendaddrv2 message
- **GIVEN** a request to build a sendaddrv2 message
- **WHEN** serializing
- **THEN** the message has the correct header and zero-length payload
