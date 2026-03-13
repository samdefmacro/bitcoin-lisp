## 1. Block Header MTP Validation
- [x] 1.1 Add `prev-hash` parameter to `validate-block-header`, remove `(declare (ignore chain-state))`, and add MTP timestamp check: reject with :time-too-old if timestamp <= MTP of previous 11 blocks
- [x] 1.2 Update callers of `validate-block-header` to pass `prev-hash`

## 2. IBD Header Chain MTP Validation
- [x] 2.1 Add MTP timestamp check to `validate-header-chain` during header sync, computing MTP from the parent entry's chain

## 3. Tests
- [x] 3.1 Add test: block with timestamp equal to MTP is rejected (:time-too-old)
- [x] 3.2 Add test: block with timestamp one second after MTP is accepted
- [x] 3.3 Add test: block with no ancestors (genesis) passes MTP check (MTP=0)
