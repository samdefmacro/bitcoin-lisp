## ADDED Requirements

### Requirement: RPC Request Rate Limiting
The system SHALL enforce a global rate limit on incoming RPC requests using a token bucket algorithm.

The default rate limit SHALL be 100 requests per second with a burst capacity of 200.

When the rate limit is exceeded, the system SHALL return HTTP 429 (Too Many Requests) without processing the request.

Rate limit parameters SHALL be configurable via global variables.

#### Scenario: Allow requests within rate limit
- **GIVEN** the RPC server is receiving requests at 50/sec
- **WHEN** a new request arrives
- **THEN** the request is processed normally

#### Scenario: Reject requests exceeding rate limit
- **GIVEN** the RPC server has exhausted its rate limit tokens
- **WHEN** a new request arrives
- **THEN** HTTP 429 Too Many Requests is returned
- **AND** the response body contains a JSON-RPC error with message "Rate limit exceeded"

#### Scenario: Allow burst of requests
- **GIVEN** the RPC server has been idle for 2 seconds
- **WHEN** 200 requests arrive simultaneously
- **THEN** all 200 requests are processed (burst capacity)

### Requirement: RPC Request Body Size Limit
The system SHALL reject RPC requests with a body exceeding 1 MB.

The size check SHALL occur before reading and parsing the request body, using the Content-Length header when available.

#### Scenario: Accept normal-sized request
- **GIVEN** an RPC request with a 500-byte JSON body
- **WHEN** the request is received
- **THEN** the request is processed normally

#### Scenario: Reject oversized request
- **GIVEN** an RPC request with Content-Length of 2,000,000 bytes
- **WHEN** the request is received
- **THEN** HTTP 413 Payload Too Large is returned
- **AND** the request body is not read or parsed

#### Scenario: Reject oversized request without Content-Length
- **GIVEN** an RPC request without Content-Length header that exceeds 1 MB during reading
- **WHEN** the body read exceeds 1 MB
- **THEN** reading is aborted and HTTP 413 Payload Too Large is returned
