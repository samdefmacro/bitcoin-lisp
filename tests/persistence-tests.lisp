(in-package #:bitcoin-lisp.tests)

(in-suite :persistence-tests)

;;;; UTXO Set Persistence Tests

(test utxo-save-load-round-trip
  "Saving and loading a UTXO set should preserve all entries."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (path (merge-pathnames "test-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory)))))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script1 (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (script2 (make-array 34 :element-type '(unsigned-byte 8) :initial-element #xA9)))
    ;; Add entries
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 50000000 script1 100 :coinbase t)
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 1 25000000 script2 100 :coinbase t)
    (bitcoin-lisp.storage:add-utxo utxo-set txid2 0 1000000 script1 200 :coinbase nil)
    ;; Save
    (bitcoin-lisp.storage:save-utxo-set utxo-set path)
    ;; Load into fresh set
    (let ((loaded-set (bitcoin-lisp.storage:make-utxo-set)))
      (is (bitcoin-lisp.storage:load-utxo-set loaded-set path))
      ;; Verify count
      (is (= 3 (bitcoin-lisp.storage:utxo-count loaded-set)))
      ;; Verify entry 1
      (let ((e1 (bitcoin-lisp.storage:get-utxo loaded-set txid1 0)))
        (is (not (null e1)))
        (is (= 50000000 (bitcoin-lisp.storage:utxo-entry-value e1)))
        (is (= 100 (bitcoin-lisp.storage:utxo-entry-height e1)))
        (is (bitcoin-lisp.storage:utxo-entry-coinbase e1))
        (is (equalp script1 (bitcoin-lisp.storage:utxo-entry-script-pubkey e1))))
      ;; Verify entry 2
      (let ((e2 (bitcoin-lisp.storage:get-utxo loaded-set txid1 1)))
        (is (not (null e2)))
        (is (= 25000000 (bitcoin-lisp.storage:utxo-entry-value e2)))
        (is (equalp script2 (bitcoin-lisp.storage:utxo-entry-script-pubkey e2))))
      ;; Verify entry 3
      (let ((e3 (bitcoin-lisp.storage:get-utxo loaded-set txid2 0)))
        (is (not (null e3)))
        (is (= 1000000 (bitcoin-lisp.storage:utxo-entry-value e3)))
        (is (= 200 (bitcoin-lisp.storage:utxo-entry-height e3)))
        (is (not (bitcoin-lisp.storage:utxo-entry-coinbase e3)))))
    ;; Cleanup
    (when (probe-file path)
      (delete-file path))))

(test utxo-load-nonexistent-file
  "Loading from nonexistent file should return NIL."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set)))
    (is (null (bitcoin-lisp.storage:load-utxo-set
               utxo-set
               (merge-pathnames "nonexistent-utxo.dat" (uiop:temporary-directory)))))))

(test utxo-empty-set-round-trip
  "Saving and loading an empty UTXO set should work."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (path (merge-pathnames "test-empty-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory))))))
    (bitcoin-lisp.storage:save-utxo-set utxo-set path)
    (let ((loaded (bitcoin-lisp.storage:make-utxo-set)))
      (is (bitcoin-lisp.storage:load-utxo-set loaded path))
      (is (= 0 (bitcoin-lisp.storage:utxo-count loaded))))
    (when (probe-file path)
      (delete-file path))))

(test utxo-dirty-flag-on-save
  "Saving should clear the dirty flag."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (path (merge-pathnames "test-dirty-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory)))))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 10))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 1000 script 1)
    (is (bitcoin-lisp.storage:utxo-set-dirty utxo-set))
    (bitcoin-lisp.storage:save-utxo-set utxo-set path)
    (is (not (bitcoin-lisp.storage:utxo-set-dirty utxo-set)))
    (when (probe-file path)
      (delete-file path))))

;;;; Header Index Persistence Tests

(test header-index-save-load-round-trip
  "Saving and loading header index should preserve entries and linkage."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-headers/"
                                      (uiop:temporary-directory))))
         (state (bitcoin-lisp.storage:init-chain-state base-path))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash state)))
    ;; Add genesis to block index
    (bitcoin-lisp.storage:add-block-index-entry
     state
     (bitcoin-lisp.storage:make-block-index-entry
      :hash genesis-hash
      :height 0
      :chain-work 0
      :status :valid))
    ;; Add a child block
    (let ((block1-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA)))
      (bitcoin-lisp.storage:add-block-index-entry
       state
       (bitcoin-lisp.storage:make-block-index-entry
        :hash block1-hash
        :height 1
        :prev-entry (bitcoin-lisp.storage:get-block-index-entry state genesis-hash)
        :chain-work 100
        :status :valid))
      (bitcoin-lisp.storage:update-chain-tip state block1-hash 1)
      ;; Save
      (bitcoin-lisp.storage:save-header-index state)
      ;; Load into fresh state
      (let ((state2 (bitcoin-lisp.storage:init-chain-state base-path)))
        (is (bitcoin-lisp.storage:load-header-index state2))
        ;; Verify genesis entry
        (let ((ge (bitcoin-lisp.storage:get-block-index-entry state2 genesis-hash)))
          (is (not (null ge)))
          (is (= 0 (bitcoin-lisp.storage:block-index-entry-height ge)))
          (is (eq :valid (bitcoin-lisp.storage:block-index-entry-status ge))))
        ;; Verify block 1 entry
        (let ((b1 (bitcoin-lisp.storage:get-block-index-entry state2 block1-hash)))
          (is (not (null b1)))
          (is (= 1 (bitcoin-lisp.storage:block-index-entry-height b1)))
          (is (= 100 (bitcoin-lisp.storage:block-index-entry-chain-work b1)))
          (is (eq :valid (bitcoin-lisp.storage:block-index-entry-status b1)))
          ;; Verify prev-entry linkage
          (let ((prev (bitcoin-lisp.storage:block-index-entry-prev-entry b1)))
            (is (not (null prev)))
            (is (equalp genesis-hash (bitcoin-lisp.storage:block-index-entry-hash prev)))))))
    ;; Cleanup
    (let ((path (merge-pathnames "headerindex.dat" base-path)))
      (when (probe-file path)
        (delete-file path)))))

;;;; Persistence Integrity Tests

(test utxo-detect-truncated-file
  "Loading a truncated UTXO file should fail (CRC mismatch)."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (path (merge-pathnames "test-truncated-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory)))))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Save a valid file
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 50000000 script 100 :coinbase t)
    (bitcoin-lisp.storage:save-utxo-set utxo-set path)
    ;; Truncate the file (remove last 10 bytes)
    (let* ((file-bytes (with-open-file (s path :direction :input
                                              :element-type '(unsigned-byte 8))
                         (let ((b (make-array (file-length s) :element-type '(unsigned-byte 8))))
                           (read-sequence b s) b)))
           (truncated (subseq file-bytes 0 (max 0 (- (length file-bytes) 10)))))
      (with-open-file (s path :direction :output :if-exists :supersede
                              :element-type '(unsigned-byte 8))
        (write-sequence truncated s)))
    ;; Loading should fail
    (let ((fresh-set (bitcoin-lisp.storage:make-utxo-set)))
      (is (null (bitcoin-lisp.storage:load-utxo-set fresh-set path))))
    (when (probe-file path) (delete-file path))))

(test utxo-detect-corrupted-file
  "Loading a UTXO file with flipped bits should fail (CRC mismatch)."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (path (merge-pathnames "test-corrupt-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory)))))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 50000000 script 100 :coinbase t)
    (bitcoin-lisp.storage:save-utxo-set utxo-set path)
    ;; Flip a byte in the middle
    (let ((file-bytes (with-open-file (s path :direction :input
                                              :element-type '(unsigned-byte 8))
                        (let ((b (make-array (file-length s) :element-type '(unsigned-byte 8))))
                          (read-sequence b s) b))))
      (setf (aref file-bytes (floor (length file-bytes) 2))
            (logxor (aref file-bytes (floor (length file-bytes) 2)) #xFF))
      (with-open-file (s path :direction :output :if-exists :supersede
                              :element-type '(unsigned-byte 8))
        (write-sequence file-bytes s)))
    (let ((fresh-set (bitcoin-lisp.storage:make-utxo-set)))
      (is (null (bitcoin-lisp.storage:load-utxo-set fresh-set path))))
    (when (probe-file path) (delete-file path))))

(test utxo-reject-unknown-version
  "Loading a UTXO file with wrong version should fail."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (path (merge-pathnames "test-badver-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory)))))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 50000000 script 100 :coinbase t)
    (bitcoin-lisp.storage:save-utxo-set utxo-set path)
    ;; Change version byte (byte 4) to 99 and recompute CRC
    (let ((file-bytes (with-open-file (s path :direction :input
                                              :element-type '(unsigned-byte 8))
                        (let ((b (make-array (file-length s) :element-type '(unsigned-byte 8))))
                          (read-sequence b s) b))))
      ;; Version is at offset 4 (after 4 magic bytes)
      (setf (aref file-bytes 4) 99)
      ;; Recompute CRC for the modified data
      (let* ((data-bytes (subseq file-bytes 0 (- (length file-bytes) 4)))
             (new-crc (bitcoin-lisp.storage:compute-crc32 data-bytes)))
        (replace file-bytes new-crc :start1 (- (length file-bytes) 4)))
      (with-open-file (s path :direction :output :if-exists :supersede
                              :element-type '(unsigned-byte 8))
        (write-sequence file-bytes s)))
    (let ((fresh-set (bitcoin-lisp.storage:make-utxo-set)))
      (is (null (bitcoin-lisp.storage:load-utxo-set fresh-set path))))
    (when (probe-file path) (delete-file path))))

(test utxo-backward-compat-old-format
  "Loading an old-format UTXO file (no magic) should succeed."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (path (merge-pathnames "test-oldfmt-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory)))))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Write old format manually: count(4) + entries (no magic, no CRC)
    (with-open-file (s path :direction :output :if-exists :supersede
                            :element-type '(unsigned-byte 8))
      ;; Count = 1
      (write-byte 1 s) (write-byte 0 s) (write-byte 0 s) (write-byte 0 s)
      ;; 36-byte key (txid + output-index)
      (write-sequence txid s)
      (write-byte 0 s) (write-byte 0 s) (write-byte 0 s) (write-byte 0 s)
      ;; 8-byte value = 1000000
      (write-byte #x40 s) (write-byte #x42 s) (write-byte #x0F s) (write-byte 0 s)
      (write-byte 0 s) (write-byte 0 s) (write-byte 0 s) (write-byte 0 s)
      ;; 4-byte height = 10
      (write-byte 10 s) (write-byte 0 s) (write-byte 0 s) (write-byte 0 s)
      ;; 1-byte coinbase = 0
      (write-byte 0 s)
      ;; 4-byte script-len = 25
      (write-byte 25 s) (write-byte 0 s) (write-byte 0 s) (write-byte 0 s)
      ;; 25-byte script
      (write-sequence script s))
    (let ((loaded (bitcoin-lisp.storage:make-utxo-set)))
      (is (bitcoin-lisp.storage:load-utxo-set loaded path))
      (is (= 1 (bitcoin-lisp.storage:utxo-count loaded)))
      (let ((entry (bitcoin-lisp.storage:get-utxo loaded txid 0)))
        (is (not (null entry)))
        (is (= 1000000 (bitcoin-lisp.storage:utxo-entry-value entry)))))
    (when (probe-file path) (delete-file path))))

(test header-index-detect-corrupted
  "Loading a corrupted header index file should fail (CRC mismatch)."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-corrupt-headers/"
                                      (uiop:temporary-directory))))
         (state (bitcoin-lisp.storage:init-chain-state base-path))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash state)))
    (bitcoin-lisp.storage:add-block-index-entry
     state
     (bitcoin-lisp.storage:make-block-index-entry
      :hash genesis-hash :height 0 :chain-work 0 :status :valid))
    (bitcoin-lisp.storage:save-header-index state)
    ;; Corrupt the file
    (let* ((path (merge-pathnames "headerindex.dat" base-path))
           (file-bytes (with-open-file (s path :direction :input
                                               :element-type '(unsigned-byte 8))
                         (let ((b (make-array (file-length s) :element-type '(unsigned-byte 8))))
                           (read-sequence b s) b))))
      (setf (aref file-bytes (floor (length file-bytes) 2))
            (logxor (aref file-bytes (floor (length file-bytes) 2)) #xFF))
      (with-open-file (s path :direction :output :if-exists :supersede
                              :element-type '(unsigned-byte 8))
        (write-sequence file-bytes s)))
    ;; Loading should fail
    (let ((state2 (bitcoin-lisp.storage:init-chain-state base-path)))
      (is (null (bitcoin-lisp.storage:load-header-index state2))))
    ;; Cleanup
    (let ((path (merge-pathnames "headerindex.dat" base-path)))
      (when (probe-file path) (delete-file path)))))

;;;; Peer Health Monitoring Tests

(test peer-health-consecutive-failures
  "Peer should be disconnected after 3 consecutive ping failures."
  (let ((peer (bitcoin-lisp.networking:make-peer)))
    (setf (bitcoin-lisp.networking:peer-state peer) :ready)
    ;; Simulate 3 ping failures
    (is (= 0 (bitcoin-lisp.networking:peer-consecutive-ping-failures peer)))
    (setf (bitcoin-lisp.networking:peer-consecutive-ping-failures peer) 2)
    ;; One more failure means disconnect
    (incf (bitcoin-lisp.networking:peer-consecutive-ping-failures peer))
    (is (>= (bitcoin-lisp.networking:peer-consecutive-ping-failures peer)
            bitcoin-lisp.networking:+max-ping-failures+))))

(test peer-pong-resets-failures
  "Receiving a pong should reset the failure counter."
  (let ((peer (bitcoin-lisp.networking:make-peer)))
    (setf (bitcoin-lisp.networking:peer-state peer) :ready)
    (setf (bitcoin-lisp.networking:peer-consecutive-ping-failures peer) 2)
    ;; Set up a matching ping/pong
    (setf (bitcoin-lisp.networking::peer-ping-nonce peer) 12345)
    (setf (bitcoin-lisp.networking::peer-last-ping-time peer) (get-internal-real-time))
    ;; Handle matching pong
    (bitcoin-lisp.networking::handle-pong peer 12345)
    ;; Failures should be reset
    (is (= 0 (bitcoin-lisp.networking:peer-consecutive-ping-failures peer)))))

;;;; Misbehavior Scoring Tests

(test peer-misbehavior-ban-threshold
  "Peer should be banned when misbehavior score reaches threshold."
  (let ((peer (bitcoin-lisp.networking:make-peer)))
    (setf (bitcoin-lisp.networking:peer-state peer) :ready)
    (setf (bitcoin-lisp.networking:peer-address peer) "192.0.2.99")
    ;; Score below threshold
    (is (not (bitcoin-lisp.networking:record-misbehavior peer 50)))
    (is (= 50 (bitcoin-lisp.networking:peer-misbehavior-score peer)))
    (is (eq :ready (bitcoin-lisp.networking:peer-state peer)))
    ;; Score reaches threshold
    (is (bitcoin-lisp.networking:record-misbehavior peer 50))
    (is (eq :banned (bitcoin-lisp.networking:peer-state peer)))
    ;; Address should be in ban list
    (is (bitcoin-lisp.networking:peer-banned-p "192.0.2.99"))
    ;; Cleanup
    (bitcoin-lisp.networking:clear-ban-list)))

(test peer-banned-p-check
  "peer-banned-p should return T for banned addresses, NIL for others."
  (bitcoin-lisp.networking:clear-ban-list)
  (is (not (bitcoin-lisp.networking:peer-banned-p "192.0.2.1")))
  ;; Manually ban an address
  (setf (gethash "192.0.2.1" bitcoin-lisp.networking:*banned-peers*)
        (+ (get-universal-time) 3600))  ; 1 hour from now
  (is (bitcoin-lisp.networking:peer-banned-p "192.0.2.1"))
  ;; Expired ban
  (setf (gethash "192.0.2.2" bitcoin-lisp.networking:*banned-peers*)
        (- (get-universal-time) 1))  ; 1 second ago
  (is (not (bitcoin-lisp.networking:peer-banned-p "192.0.2.2")))
  (bitcoin-lisp.networking:clear-ban-list))

(test peer-invalid-block-immediate-ban
  "Sending an invalid block should result in immediate ban (+100)."
  (let ((peer (bitcoin-lisp.networking:make-peer)))
    (setf (bitcoin-lisp.networking:peer-state peer) :ready)
    (setf (bitcoin-lisp.networking:peer-address peer) "192.0.2.100")
    ;; One invalid block = +100 = immediate ban
    (is (bitcoin-lisp.networking:record-misbehavior peer 100))
    (is (eq :banned (bitcoin-lisp.networking:peer-state peer)))
    (bitcoin-lisp.networking:clear-ban-list)))

;;;; Block Timeout Peer Rotation Tests

(test block-timeout-count-tracking
  "Block timeouts should be tracked per peer."
  (let ((peer (bitcoin-lisp.networking:make-peer)))
    (is (= 0 (bitcoin-lisp.networking:peer-block-timeout-count peer)))
    ;; First timeout - not yet disconnect
    (is (not (bitcoin-lisp.networking:record-block-timeout peer)))
    (is (= 1 (bitcoin-lisp.networking:peer-block-timeout-count peer)))
    ;; Second timeout
    (is (not (bitcoin-lisp.networking:record-block-timeout peer)))
    (is (= 2 (bitcoin-lisp.networking:peer-block-timeout-count peer)))
    ;; Third timeout - should disconnect
    (is (bitcoin-lisp.networking:record-block-timeout peer))
    (is (= 3 (bitcoin-lisp.networking:peer-block-timeout-count peer)))))

;;;; Chain Reorganization Tests

(test find-fork-point-same-chain
  "Fork point of entries on the same chain should be the earlier one."
  (let ((genesis (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :height 0
                  :chain-work 1)))
    (let ((block1 (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
                   :height 1
                   :prev-entry genesis
                   :chain-work 2)))
      (let ((block2 (bitcoin-lisp.storage:make-block-index-entry
                     :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
                     :height 2
                     :prev-entry block1
                     :chain-work 3)))
        ;; Fork point of block2 and block1 should be genesis (since block1 is parent)
        ;; Actually fork point should be block1 since it's on the path of both
        (let ((fork (bitcoin-lisp.validation:find-fork-point block2 block1)))
          (is (not (null fork)))
          (is (= 1 (bitcoin-lisp.storage:block-index-entry-height fork))))))))

(test find-fork-point-divergent-chains
  "Fork point of divergent chains should be their common ancestor."
  (let ((genesis (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :height 0
                  :chain-work 1)))
    ;; Chain A: genesis -> A1 -> A2
    (let* ((a1 (bitcoin-lisp.storage:make-block-index-entry
                :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 10)
                :height 1
                :prev-entry genesis
                :chain-work 2))
           (a2 (bitcoin-lisp.storage:make-block-index-entry
                :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 11)
                :height 2
                :prev-entry a1
                :chain-work 3)))
      ;; Chain B: genesis -> B1 -> B2
      (let* ((b1 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 20)
                  :height 1
                  :prev-entry genesis
                  :chain-work 2))
             (b2 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 21)
                  :height 2
                  :prev-entry b1
                  :chain-work 4)))
        (let ((fork (bitcoin-lisp.validation:find-fork-point a2 b2)))
          (is (not (null fork)))
          (is (= 0 (bitcoin-lisp.storage:block-index-entry-height fork)))
          (is (equalp (bitcoin-lisp.storage:block-index-entry-hash genesis)
                      (bitcoin-lisp.storage:block-index-entry-hash fork))))))))

(test reorg-undo-data-round-trip
  "apply-block-to-utxo-set returns undo data that disconnect-block-from-utxo-set can restore."
  ;; Build a minimal block with one coinbase tx and one spending tx
  (let* ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
         ;; Pre-existing UTXO that will be spent by a tx in our block
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xDD))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Add pre-existing UTXO
    (bitcoin-lisp.storage:add-utxo utxo-set prev-txid 0 9000000 script 5 :coinbase nil)
    (is (= 1 (bitcoin-lisp.storage:utxo-count utxo-set)))

    ;; Build a block:
    ;; - coinbase tx (txid: all #x01) with one output of 5 BTC
    ;; - spending tx (txid: all #x02) spending prev-txid:0, creating one output
    (let* ((coinbase-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x01))
           (spend-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x02))
           (null-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
           (coinbase-tx (bitcoin-lisp.serialization:make-transaction
                         :version 1
                         :inputs (list (bitcoin-lisp.serialization:make-tx-in
                                        :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                          :hash null-hash :index #xFFFFFFFF)
                                        :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                                  :initial-element 1)))
                         :outputs (list (bitcoin-lisp.serialization:make-tx-out
                                         :value 500000000
                                         :script-pubkey script))
                         :lock-time 0
                         :cached-hash coinbase-txid))
           (spending-tx (bitcoin-lisp.serialization:make-transaction
                         :version 1
                         :inputs (list (bitcoin-lisp.serialization:make-tx-in
                                        :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                          :hash prev-txid :index 0)
                                        :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                                  :initial-element 2)))
                         :outputs (list (bitcoin-lisp.serialization:make-tx-out
                                         :value 8000000
                                         :script-pubkey script))
                         :lock-time 0
                         :cached-hash spend-txid))
           (block-header (bitcoin-lisp.serialization:make-block-header
                          :version 1
                          :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                          :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                          :timestamp 0 :bits 0 :nonce 0
                          :cached-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB)))
           (block (bitcoin-lisp.serialization:make-bitcoin-block
                   :header block-header
                   :transactions (list coinbase-tx spending-tx))))

      ;; Apply block: should add coinbase & spending-tx outputs, remove prev-txid:0
      (let ((spent-utxos (bitcoin-lisp.storage:apply-block-to-utxo-set utxo-set block 10)))
        ;; Verify undo data captured the spent UTXO
        (is (= 1 (length spent-utxos)))
        (let ((undo-entry (first spent-utxos)))
          (is (equalp prev-txid (first undo-entry)))
          (is (= 0 (second undo-entry)))
          (is (= 9000000 (bitcoin-lisp.storage:utxo-entry-value (third undo-entry)))))

        ;; After apply: coinbase output + spending tx output = 2 new, minus 1 spent = 2 total
        (is (= 2 (bitcoin-lisp.storage:utxo-count utxo-set)))
        (is (bitcoin-lisp.storage:utxo-exists-p utxo-set coinbase-txid 0))
        (is (bitcoin-lisp.storage:utxo-exists-p utxo-set spend-txid 0))
        (is (not (bitcoin-lisp.storage:utxo-exists-p utxo-set prev-txid 0)))

        ;; Now disconnect the block using undo data
        (bitcoin-lisp.storage:disconnect-block-from-utxo-set utxo-set block spent-utxos)

        ;; After disconnect: only the original pre-existing UTXO should remain
        (is (= 1 (bitcoin-lisp.storage:utxo-count utxo-set)))
        (is (bitcoin-lisp.storage:utxo-exists-p utxo-set prev-txid 0))
        (is (not (bitcoin-lisp.storage:utxo-exists-p utxo-set coinbase-txid 0)))
        (is (not (bitcoin-lisp.storage:utxo-exists-p utxo-set spend-txid 0)))
        ;; Verify restored UTXO has correct value
        (is (= 9000000 (bitcoin-lisp.storage:utxo-entry-value
                          (bitcoin-lisp.storage:get-utxo utxo-set prev-txid 0))))))))

;;;; Block Timeout and Retry Tests

(test timed-out-blocks-become-re-requestable
  "After retry-timed-out-requests, timed-out blocks should be requestable again."
  (let* ((bitcoin-lisp.networking::*ibd-context*
           (bitcoin-lisp.networking::make-ibd))
         (ctx bitcoin-lisp.networking::*ibd-context*)
         (hash1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xF1))
         (hash2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xF2))
         (peer (bitcoin-lisp.networking:make-peer)))
    (setf (bitcoin-lisp.networking:peer-state peer) :ready)
    ;; Add blocks to pending
    (setf (gethash hash1 (bitcoin-lisp.networking::ibd-context-pending-blocks ctx)) 10)
    (setf (gethash hash2 (bitcoin-lisp.networking::ibd-context-pending-blocks ctx)) 11)
    ;; Mark both as in-flight from the peer with an old timestamp (simulating timeout)
    (let ((old-time (- (get-internal-real-time)
                       (* 120 internal-time-units-per-second))))
      (setf (gethash hash1 (bitcoin-lisp.networking::ibd-context-in-flight ctx))
            (cons peer old-time))
      (setf (gethash hash2 (bitcoin-lisp.networking::ibd-context-in-flight ctx))
            (cons peer old-time)))
    ;; Verify both are in-flight
    (is (= 2 (hash-table-count (bitcoin-lisp.networking::ibd-context-in-flight ctx))))
    ;; Retry timed-out requests
    (let ((retried (bitcoin-lisp.networking::retry-timed-out-requests)))
      (is (= 2 retried)))
    ;; In-flight should be empty now
    (is (= 0 (hash-table-count (bitcoin-lisp.networking::ibd-context-in-flight ctx))))
    ;; Blocks should still be in pending (re-requestable)
    (is (= 2 (hash-table-count (bitcoin-lisp.networking::ibd-context-pending-blocks ctx))))
    ;; get-next-blocks-to-request should return them
    (let ((next (bitcoin-lisp.networking::get-next-blocks-to-request 10)))
      (is (= 2 (length next))))))

;;;; Sync Resume Simulation Test

(test simulate-restart-resume
  "Simulating a node restart should resume from persisted state."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-restart/"
                                      (uiop:temporary-directory))))
         ;; Step 1: Create initial state at height 50
         (state1 (bitcoin-lisp.storage:init-chain-state base-path))
         (utxo1 (bitcoin-lisp.storage:make-utxo-set)))
    ;; Add genesis to index
    (let ((genesis-hash (bitcoin-lisp.storage:best-block-hash state1)))
      (bitcoin-lisp.storage:add-block-index-entry
       state1
       (bitcoin-lisp.storage:make-block-index-entry
        :hash genesis-hash :height 0 :chain-work 0 :status :valid))
      ;; Build a chain of 3 block entries
      (let ((prev-entry (bitcoin-lisp.storage:get-block-index-entry state1 genesis-hash)))
        (loop for h from 1 to 3
              for hash = (make-array 32 :element-type '(unsigned-byte 8) :initial-element h)
              do (let ((entry (bitcoin-lisp.storage:make-block-index-entry
                               :hash hash :height h :prev-entry prev-entry
                               :chain-work (* h 100) :status :valid)))
                   (bitcoin-lisp.storage:add-block-index-entry state1 entry)
                   (bitcoin-lisp.storage:update-chain-tip state1 hash h)
                   (setf prev-entry entry)))))
    ;; Add some UTXOs as if blocks were connected
    (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC))
          (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
      (bitcoin-lisp.storage:add-utxo utxo1 txid 0 5000000000 script 1 :coinbase t)
      (bitcoin-lisp.storage:add-utxo utxo1 txid 1 2500000000 script 1 :coinbase t))
    ;; Save everything (simulating shutdown)
    (bitcoin-lisp.storage:save-state state1)
    (bitcoin-lisp.storage:save-utxo-set utxo1
                                         (bitcoin-lisp.storage:utxo-set-file-path base-path))
    (bitcoin-lisp.storage:save-header-index state1)
    ;; Step 2: Create a fresh state (simulating restart)
    (let ((state2 (bitcoin-lisp.storage:init-chain-state base-path))
          (utxo2 (bitcoin-lisp.storage:make-utxo-set)))
      ;; Load persisted state
      (bitcoin-lisp.storage:load-state state2)
      (bitcoin-lisp.storage:load-utxo-set utxo2
                                           (bitcoin-lisp.storage:utxo-set-file-path base-path))
      (bitcoin-lisp.storage:load-header-index state2)
      ;; Verify chain state resumed
      (is (= 3 (bitcoin-lisp.storage:current-height state2)))
      ;; Verify UTXO set resumed
      (is (= 2 (bitcoin-lisp.storage:utxo-count utxo2)))
      (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC)))
        (is (bitcoin-lisp.storage:utxo-exists-p utxo2 txid 0))
        (is (= 5000000000 (bitcoin-lisp.storage:utxo-entry-value
                            (bitcoin-lisp.storage:get-utxo utxo2 txid 0)))))
      ;; Verify header index resumed with linkage
      (let* ((tip-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
             (tip-entry (bitcoin-lisp.storage:get-block-index-entry state2 tip-hash)))
        (is (not (null tip-entry)))
        (is (= 3 (bitcoin-lisp.storage:block-index-entry-height tip-entry)))
        (is (= 300 (bitcoin-lisp.storage:block-index-entry-chain-work tip-entry)))
        ;; Verify chain linkage exists
        (let ((prev (bitcoin-lisp.storage:block-index-entry-prev-entry tip-entry)))
          (is (not (null prev)))
          (is (= 2 (bitcoin-lisp.storage:block-index-entry-height prev))))))
    ;; Cleanup
    (dolist (file '("chainstate.dat" "utxoset.dat" "headerindex.dat"))
      (let ((path (merge-pathnames file base-path)))
        (when (probe-file path)
          (delete-file path))))))

;;;; Reorg and Persistence Edge-Case Tests

(defun make-reorg-test-block (prev-hash block-hash height &key (value 5000000000))
  "Create a minimal test block for reorg tests."
  (let* ((coinbase-tx (bitcoin-lisp.serialization:make-transaction
                       :version 1
                       :inputs (list (bitcoin-lisp.serialization:make-tx-in
                                      :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                        :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                          :initial-element 0)
                                                        :index #xFFFFFFFF)
                                      :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                                :initial-element 1)))
                       :outputs (list (bitcoin-lisp.serialization:make-tx-out
                                       :value value
                                       :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                  :initial-element #x76)))
                       :lock-time 0
                       :cached-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 0)))
                                      ;; Make txid unique per block using full block-hash info
                                      (setf (aref h 0) (aref block-hash 0))
                                      (setf (aref h 1) (aref block-hash 1))
                                      (setf (aref h 2) #xBB)
                                      h)))
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block prev-hash
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp (+ 1231006505 (* height 600))
                  :bits #x1d00ffff
                  :nonce 0
                  :cached-hash block-hash)))
    (bitcoin-lisp.serialization:make-bitcoin-block
     :header header
     :transactions (list coinbase-tx))))

(defun make-test-chain-hashes (prefix count)
  "Generate COUNT unique 32-byte hashes with PREFIX byte for chain identification."
  (loop for i from 1 to count
        collect (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                  (setf (aref h 0) prefix)
                  (setf (aref h 1) i)
                  h)))

(test multi-block-reorg-3-deep
  "A reorg of 3+ blocks should correctly switch chains."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-reorg-deep/"
                                      (uiop:temporary-directory))))
         (chain-state (bitcoin-lisp.storage:init-chain-state base-path))
         (utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (block-store (bitcoin-lisp.storage:init-block-store base-path))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
    ;; Clear undo data
    (clrhash bitcoin-lisp.validation::*block-undo-data*)
    ;; Add genesis index entry
    (bitcoin-lisp.storage:add-block-index-entry
     chain-state
     (bitcoin-lisp.storage:make-block-index-entry
      :hash genesis-hash :height 0 :chain-work 1 :status :valid))
    ;; Build chain A: genesis -> A1 -> A2 -> A3 (3 blocks, lower work)
    (let ((chain-a-hashes (make-test-chain-hashes #xA0 3)))
      (let ((prev-hash genesis-hash))
        (loop for h from 1 to 3
              for block-hash in chain-a-hashes
              do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                   (bitcoin-lisp.validation:connect-block
                    block chain-state block-store utxo-set)
                   (setf prev-hash block-hash))))
      ;; Verify chain A is current
      (is (= 3 (bitcoin-lisp.storage:current-height chain-state)))
      (is (equalp (third chain-a-hashes)
                  (bitcoin-lisp.storage:best-block-hash chain-state)))
      ;; Count UTXOs from chain A (3 coinbase outputs)
      (is (= 3 (bitcoin-lisp.storage:utxo-count utxo-set)))
      ;; Build chain B: genesis -> B1 -> B2 -> B3 -> B4 (4 blocks, more work)
      (let ((chain-b-hashes (make-test-chain-hashes #xB0 4)))
        (let ((prev-hash genesis-hash))
          (loop for h from 1 to 4
                for block-hash in chain-b-hashes
                do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                     (bitcoin-lisp.validation:connect-block
                      block chain-state block-store utxo-set)
                     (setf prev-hash block-hash))))
        ;; After reorg: chain B should be active (4 blocks, more work)
        (is (= 4 (bitcoin-lisp.storage:current-height chain-state)))
        (is (equalp (fourth chain-b-hashes)
                    (bitcoin-lisp.storage:best-block-hash chain-state)))
        ;; UTXOs: chain A's 3 coinbase outputs disconnected, chain B's 4 connected
        (is (= 4 (bitcoin-lisp.storage:utxo-count utxo-set)))))
    ;; Cleanup
    (clrhash bitcoin-lisp.validation::*block-undo-data*)))

(test reorg-missing-undo-data-graceful
  "Reorg with missing undo data should not corrupt the UTXO set or crash."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-reorg-noundo/"
                                      (uiop:temporary-directory))))
         (chain-state (bitcoin-lisp.storage:init-chain-state base-path))
         (utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (block-store (bitcoin-lisp.storage:init-block-store base-path))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
    (clrhash bitcoin-lisp.validation::*block-undo-data*)
    (bitcoin-lisp.storage:add-block-index-entry
     chain-state
     (bitcoin-lisp.storage:make-block-index-entry
      :hash genesis-hash :height 0 :chain-work 1 :status :valid))
    ;; Build chain A: genesis -> A1 -> A2
    (let ((chain-a-hashes (make-test-chain-hashes #xC0 2)))
      (let ((prev-hash genesis-hash))
        (loop for h from 1 to 2
              for block-hash in chain-a-hashes
              do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                   (bitcoin-lisp.validation:connect-block
                    block chain-state block-store utxo-set)
                   (setf prev-hash block-hash))))
      ;; Deliberately clear undo data to simulate missing undo
      (clrhash bitcoin-lisp.validation::*block-undo-data*)
      ;; Now build chain B with more work: genesis -> B1 -> B2 -> B3
      (let ((chain-b-hashes (make-test-chain-hashes #xD0 3)))
        (let ((prev-hash genesis-hash))
          (loop for h from 1 to 3
                for block-hash in chain-b-hashes
                do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                     (bitcoin-lisp.validation:connect-block
                      block chain-state block-store utxo-set)
                     (setf prev-hash block-hash))))
        ;; Should not crash; chain tip should be updated to chain B
        (is (= 3 (bitcoin-lisp.storage:current-height chain-state)))
        (is (equalp (third chain-b-hashes)
                    (bitcoin-lisp.storage:best-block-hash chain-state)))))
    (clrhash bitcoin-lisp.validation::*block-undo-data*)))

(test persistence-round-trip-after-reorg
  "Chain state and UTXO set should be consistent after save/load following a reorg."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-reorg-persist/"
                                      (uiop:temporary-directory))))
         (chain-state (bitcoin-lisp.storage:init-chain-state base-path))
         (utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (block-store (bitcoin-lisp.storage:init-block-store base-path))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
    (clrhash bitcoin-lisp.validation::*block-undo-data*)
    (bitcoin-lisp.storage:add-block-index-entry
     chain-state
     (bitcoin-lisp.storage:make-block-index-entry
      :hash genesis-hash :height 0 :chain-work 1 :status :valid))
    ;; Build chain A (2 blocks)
    (let ((chain-a-hashes (make-test-chain-hashes #xE0 2)))
      (let ((prev-hash genesis-hash))
        (loop for h from 1 to 2
              for block-hash in chain-a-hashes
              do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                   (bitcoin-lisp.validation:connect-block
                    block chain-state block-store utxo-set)
                   (setf prev-hash block-hash)))))
    ;; Build chain B (3 blocks, triggers reorg)
    (let ((chain-b-hashes (make-test-chain-hashes #xF0 3)))
      (let ((prev-hash genesis-hash))
        (loop for h from 1 to 3
              for block-hash in chain-b-hashes
              do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                   (bitcoin-lisp.validation:connect-block
                    block chain-state block-store utxo-set)
                   (setf prev-hash block-hash))))
      ;; After reorg: chain B is active
      (is (= 3 (bitcoin-lisp.storage:current-height chain-state)))
      (let ((utxo-count-before (bitcoin-lisp.storage:utxo-count utxo-set)))
        ;; Save state
        (bitcoin-lisp.storage:save-state chain-state)
        (bitcoin-lisp.storage:save-utxo-set utxo-set
                                             (bitcoin-lisp.storage:utxo-set-file-path base-path))
        (bitcoin-lisp.storage:save-header-index chain-state)
        ;; Load into fresh state
        (let ((state2 (bitcoin-lisp.storage:init-chain-state base-path))
              (utxo2 (bitcoin-lisp.storage:make-utxo-set)))
          (bitcoin-lisp.storage:load-state state2)
          (bitcoin-lisp.storage:load-utxo-set utxo2
                                               (bitcoin-lisp.storage:utxo-set-file-path base-path))
          (bitcoin-lisp.storage:load-header-index state2)
          ;; Verify chain state matches
          (is (= 3 (bitcoin-lisp.storage:current-height state2)))
          (is (equalp (third chain-b-hashes)
                      (bitcoin-lisp.storage:best-block-hash state2)))
          ;; Verify UTXO count matches
          (is (= utxo-count-before (bitcoin-lisp.storage:utxo-count utxo2)))
          ;; Verify header index has entries from both chains
          (let ((tip-entry (bitcoin-lisp.storage:get-block-index-entry
                            state2 (third chain-b-hashes))))
            (is (not (null tip-entry)))
            (is (= 3 (bitcoin-lisp.storage:block-index-entry-height tip-entry)))))))
    ;; Cleanup
    (clrhash bitcoin-lisp.validation::*block-undo-data*)
    (dolist (file '("chainstate.dat" "utxoset.dat" "headerindex.dat"))
      (let ((path (merge-pathnames file base-path)))
        (when (probe-file path) (delete-file path))))))

(test utxo-consistency-save-load-during-sync
  "UTXO set should remain consistent through save/load cycles during block processing."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-utxo-sync/"
                                      (uiop:temporary-directory))))
         (utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (utxo-path (bitcoin-lisp.storage:utxo-set-file-path base-path))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Simulate syncing several blocks with save/load between them
    ;; Block 1: add coinbase UTXO
    (let ((txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11)))
      (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 5000000000 script 1 :coinbase t)
      ;; Save and reload (simulating periodic checkpoint)
      (bitcoin-lisp.storage:save-utxo-set utxo-set utxo-path)
      (let ((reloaded (bitcoin-lisp.storage:make-utxo-set)))
        (is (bitcoin-lisp.storage:load-utxo-set reloaded utxo-path))
        (is (= 1 (bitcoin-lisp.storage:utxo-count reloaded)))
        (is (bitcoin-lisp.storage:utxo-exists-p reloaded txid1 0))
        ;; Continue syncing on reloaded set
        ;; Block 2: add another UTXO, spend first one
        (let ((txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22)))
          (bitcoin-lisp.storage:add-utxo reloaded txid2 0 4999000000 script 2)
          (bitcoin-lisp.storage:remove-utxo reloaded txid1 0)
          ;; Save and reload again
          (bitcoin-lisp.storage:save-utxo-set reloaded utxo-path)
          (let ((reloaded2 (bitcoin-lisp.storage:make-utxo-set)))
            (is (bitcoin-lisp.storage:load-utxo-set reloaded2 utxo-path))
            (is (= 1 (bitcoin-lisp.storage:utxo-count reloaded2)))
            (is (not (bitcoin-lisp.storage:utxo-exists-p reloaded2 txid1 0)))
            (is (bitcoin-lisp.storage:utxo-exists-p reloaded2 txid2 0))
            ;; Verify value preserved
            (let ((entry (bitcoin-lisp.storage:get-utxo reloaded2 txid2 0)))
              (is (= 4999000000 (bitcoin-lisp.storage:utxo-entry-value entry))))))))
    ;; Cleanup
    (when (probe-file utxo-path) (delete-file utxo-path))))

;;;; Out-of-Order Block Queue Tests

(test drain-block-queue-empty
  "Draining an empty queue should return 0."
  (let ((bitcoin-lisp.networking::*ibd-context*
          (bitcoin-lisp.networking::make-ibd)))
    (let ((state (bitcoin-lisp.storage:init-chain-state
                  (merge-pathnames "test-drain/" (uiop:temporary-directory))))
          (utxo-set (bitcoin-lisp.storage:make-utxo-set))
          (block-store (bitcoin-lisp.storage:init-block-store
                        (merge-pathnames "test-drain/" (uiop:temporary-directory)))))
      (is (= 0 (bitcoin-lisp.networking::drain-block-queue state utxo-set block-store))))))
