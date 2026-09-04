(in-package #:bitcoin-lisp.tests)

(def-suite :bitcoin-core-sighash-tests
  :description "Bitcoin Core sighash.json compatibility tests"
  :in :bitcoin-lisp-tests)

(in-suite :bitcoin-core-sighash-tests)

(defun load-sighash-tests ()
  "Load sighash test vectors from Bitcoin Core's sighash.json."
  (let ((path (merge-pathnames
               "refs/bitcoin/src/test/data/sighash.json"
               (asdf:system-source-directory :bitcoin-lisp))))
    (with-open-file (stream path :direction :input)
      (yason:parse stream))))

(test sighash-json-vectors
  "Run all Bitcoin Core sighash.json test vectors."
  (let ((tests (load-sighash-tests))
        (passed 0)
        (failed 0)
        (failures '()))
    (dolist (test-case tests)
      ;; Skip the header comment (first element is a list of strings)
      (when (and (listp test-case)
                 (= (length test-case) 5)
                 (stringp (first test-case)))
        (let* ((raw-tx-hex (first test-case))
               (script-hex (second test-case))
               (input-index (third test-case))
               (hash-type-raw (fourth test-case))
               (expected-hex (fifth test-case)))
          (handler-case
              (let* ((tx-bytes (bl.crypto:hex-to-bytes raw-tx-hex))
                     (tx (bl.ser:parse-tx-payload tx-bytes))
                     (subscript (bl.crypto:hex-to-bytes script-hex))
                     ;; hashType can be negative (signed int32), mask to unsigned
                     (hash-type (logand hash-type-raw #xFFFFFFFF))
                     (computed (bl.interop:compute-legacy-sighash
                                tx input-index subscript hash-type))
                     ;; sighash.json uses display byte order (reversed from internal)
                     (expected (reverse (bl.crypto:hex-to-bytes expected-hex))))
                (if (equalp computed expected)
                    (incf passed)
                    (progn
                      (incf failed)
                      (when (<= (length failures) 10)
                        (push (list :index (+ passed failed)
                                    :input-index input-index
                                    :hash-type hash-type
                                    :expected expected-hex
                                    :computed (bl.crypto:bytes-to-hex computed))
                              failures)))))
            (error (e)
              (incf failed)
              (when (<= (length failures) 10)
                (push (list :index (+ passed failed)
                            :error (format nil "~A" e))
                      failures)))))))

    (format t "~%Sighash Tests: ~D passed, ~D failed~%" passed failed)
    (when failures
      (format t "~%Failures (first ~D):~%" (length failures))
      (dolist (f (reverse failures))
        (format t "  ~A~%" f)))

    (is (zerop failed)
        "All sighash tests must pass. ~D failed." failed)))

;;;; Transaction versions with bit 31 set
;;;
;;; Core's CTransaction::version is a uint32_t (primitives/transaction.h:293)
;;; and no consensus rule constrains its value, so 0x80000002 is a legal
;;; version and both witness preimages carry its four octets verbatim:
;;; `ss << txTo.version' in SignatureHash (script/interpreter.cpp:1646) and
;;; `ss << tx_to.version' in SignatureHashSchnorr (:1520). Our slot is
;;; (signed-byte 32) -- that is what br-read-i32-le reads back off the wire --
;;; so the value reaches the preimage writers NEGATIVE and they must write the
;;; same 32 bits rather than reject it. The expected hashes below are
;;; assembled here from literal octets, so they share no encoder with the code
;;; under test.

(defconstant +sighash-version-bit31+ -2147483646
  "Transaction version 0x80000002 as the (signed-byte 32) slot holds it.")

(defconstant +sighash-bit31-value+ 100000
  "Satoshis on the output the version-0x80000002 fixtures spend.")

(defun %sh-le (value nbytes)
  "VALUE's low NBYTES octets, little-endian. The reference encoder for these
tests: it shares no code with the buf-set-* writers whose output it checks."
  (let ((out (make-array nbytes :element-type '(unsigned-byte 8))))
    (dotimes (i nbytes out)
      (setf (aref out i) (ldb (byte 8 (* 8 i)) value)))))

(defun %sh-cat (&rest parts)
  "One byte vector from a mix of octets and byte sequences."
  (coerce (loop for part in parts
                if (integerp part) collect part
                else append (coerce part 'list))
          '(simple-array (unsigned-byte 8) (*))))

(defun %sh-var-bytes (bytes)
  "CompactSize length prefix then BYTES. Only the one-octet length is needed
here, and the assertion keeps a longer fixture from encoding silently wrong."
  (assert (< (length bytes) #xfd))
  (%sh-cat (length bytes) bytes))

(defun %sh-bit31-tx (spent-script)
  "A one-input, one-output transaction of version 0x80000002 spending a single
output locked by SPENT-SCRIPT. Returns (values tx utxo)."
  (values (bl.ser:make-transaction
           :version +sighash-version-bit31+
           :inputs (vector (bl.ser:make-tx-in
                            :previous-output
                            (bl.ser:make-outpoint
                             :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                  :initial-element #x11)
                             :index 1)
                            :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                            :sequence #xfffffffd))
           :outputs (vector (bl.ser:make-tx-out
                             :value (- +sighash-bit31-value+ 1000)
                             :script-pubkey spent-script))
           :lock-time 500000)
          (bl.store:make-utxo-entry
           :value +sighash-bit31-value+ :script-pubkey spent-script :height 1)))

(defun %sh-bit31-p2wpkh ()
  "A version-0x80000002 P2WPKH spend. Returns (values tx utxo privkey pubkey
script-code), where script-code is BIP 143's P2PKH-shaped scriptCode."
  (let* ((sk (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
         (pub (bl.crypto:derive-public-key sk :compressed t))
         (pkh (bl.crypto:hash160 pub)))
    (multiple-value-bind (tx utxo) (%sh-bit31-tx (%sh-cat #x00 #x14 pkh))
      (values tx utxo sk pub (%sh-cat #x76 #xa9 #x14 pkh #x88 #xac)))))

(defun %sh-bit31-p2tr ()
  "A version-0x80000002 P2TR key-path spend. Returns (values tx utxo
tweaked-privkey)."
  (let* ((sk (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
         (tweaked (bl.crypto:taproot-tweak-private-key sk)))
    (multiple-value-bind (tx utxo)
        (%sh-bit31-tx (%sh-cat #x51 #x20 (bl.crypto:derive-xonly-pubkey tweaked)))
      (values tx utxo tweaked))))

(defun %sh-bip143-reference (tx utxo script-code)
  "hash256 of the BIP 143 SIGHASH_ALL preimage for input 0 of TX, assembled
from the specification's field list. The version field is the literal
0x80000002 in little-endian order, so this pins the octets instead of
re-deriving them from the slot."
  (let* ((in (aref (bl.ser:transaction-inputs tx) 0))
         (prevout (bl.ser:tx-in-previous-output in))
         (out (aref (bl.ser:transaction-outputs tx) 0))
         (serialized-prevout (%sh-cat (bl.ser:outpoint-hash prevout)
                                      (%sh-le (bl.ser:outpoint-index prevout) 4)))
         (serialized-sequence (%sh-le (bl.ser:tx-in-sequence in) 4))
         (serialized-output (%sh-cat (%sh-le (bl.ser:tx-out-value out) 8)
                                     (%sh-var-bytes
                                      (bl.ser:tx-out-script-pubkey out)))))
    (bl.crypto:hash256
     (%sh-cat #x02 #x00 #x00 #x80                     ; nVersion
              (bl.crypto:hash256 serialized-prevout)  ; hashPrevouts
              (bl.crypto:hash256 serialized-sequence) ; hashSequence
              serialized-prevout                      ; outpoint
              (%sh-var-bytes script-code)             ; scriptCode
              (%sh-le (bl.store:utxo-entry-value utxo) 8)
              serialized-sequence                     ; nSequence
              (bl.crypto:hash256 serialized-output)   ; hashOutputs
              (%sh-le (bl.ser:transaction-lock-time tx) 4)
              (%sh-le 1 4)))))                        ; SIGHASH_ALL

(defun %sh-bip341-reference (tx utxo)
  "TapSighash of the BIP 341 SigMsg for input 0 of TX: SIGHASH_DEFAULT, key
path, no annex. Same construction as %sh-bip143-reference -- the version is
the literal 0x80000002 in little-endian order."
  (let* ((in (aref (bl.ser:transaction-inputs tx) 0))
         (prevout (bl.ser:tx-in-previous-output in))
         (out (aref (bl.ser:transaction-outputs tx) 0)))
    (bl.crypto:tagged-hash
     "TapSighash"
     (%sh-cat #x00                                    ; epoch
              #x00                                    ; hash_type SIGHASH_DEFAULT
              #x02 #x00 #x00 #x80                     ; nVersion
              (%sh-le (bl.ser:transaction-lock-time tx) 4)
              (bl.crypto:sha256
               (%sh-cat (bl.ser:outpoint-hash prevout)
                        (%sh-le (bl.ser:outpoint-index prevout) 4)))
              (bl.crypto:sha256
               (%sh-le (bl.store:utxo-entry-value utxo) 8))
              (bl.crypto:sha256
               (%sh-var-bytes (bl.store:utxo-entry-script-pubkey utxo)))
              (bl.crypto:sha256 (%sh-le (bl.ser:tx-in-sequence in) 4))
              (bl.crypto:sha256
               (%sh-cat (%sh-le (bl.ser:tx-out-value out) 8)
                        (%sh-var-bytes (bl.ser:tx-out-script-pubkey out))))
              #x00                                    ; spend_type
              (%sh-le 0 4)))))                        ; input_index

(test bip143-sighash-version-bit31
  "BIP 143 preimage of a version-0x80000002 transaction: the four version
octets are 02 00 00 80, as Core streams them. The slot is negative, so before
the fix buf-set-u32-le TYPE-ERRORed here instead of hashing anything."
  (multiple-value-bind (tx utxo sk pub script-code) (%sh-bit31-p2wpkh)
    (declare (ignore sk pub))
    ;; The fixture is the wire case: a serialized version of 0x80000002.
    (is (equalp #(#x02 #x00 #x00 #x80)
                (subseq (bl.ser:serialize-transaction tx) 0 4)))
    (let ((bl.interop:*current-tx* tx)
          (bl.interop:*current-input-index* 0)
          (bl.interop:*precomputed-sighash* nil))
      (is (equalp (%sh-bip143-reference tx utxo script-code)
                  (bl.interop:compute-bip143-sighash
                   script-code (bl.store:utxo-entry-value utxo) 1))))))

(test bip341-sighash-version-bit31
  "BIP 341 SigMsg of a version-0x80000002 transaction, same rule as BIP 143."
  (multiple-value-bind (tx utxo tweaked) (%sh-bit31-p2tr)
    (declare (ignore tweaked))
    (let* ((spent (vector utxo))
           (bl.interop:*current-tx* tx)
           (bl.interop:*current-spent-utxos* spent)
           (bl.interop:*current-input-index* 0)
           (bl.interop:*precomputed-sighash*
             (bl.interop:init-precomputed-sighash tx spent)))
      (is (equalp (%sh-bip341-reference tx utxo)
                  (bl.interop:compute-bip341-sighash
                   (bl.store:utxo-entry-value utxo) 0 nil nil))))))

(test validate-input-script-p2wpkh-version-bit31
  "End to end: a correctly signed P2WPKH input of a version-0x80000002
transaction verifies. Before the fix the TYPE-ERROR from the preimage writer
escaped validate-input-script, and the sequential validate-block-scripts loop
has no handler -- so a block Core accepts aborted validation here."
  (multiple-value-bind (tx utxo sk pub script-code) (%sh-bit31-p2wpkh)
    (let* ((bl.interop:*script-flags* bl.val:+standard-script-verify-flags+)
           (bl.interop:*current-tx* tx)
           (bl.interop:*current-input-index* 0)
           (bl.interop:*precomputed-sighash* nil)
           (sig (%sh-cat (bl.crypto:sign-ecdsa
                          sk (bl.interop:compute-bip143-sighash
                              script-code (bl.store:utxo-entry-value utxo) 1))
                         1)))                         ; SIGHASH_ALL byte
      (setf (bl.ser:transaction-witness tx) (vector (list sig pub)))
      (is-true (bl.val:validate-input-script tx 0 utxo)))))

(test validate-input-script-p2tr-version-bit31
  "End to end for the taproot key path: a correctly signed P2TR input of a
version-0x80000002 transaction verifies."
  (multiple-value-bind (tx utxo tweaked) (%sh-bit31-p2tr)
    (let* ((spent (vector utxo))
           (bl.interop:*script-flags* bl.val:+standard-script-verify-flags+)
           (bl.interop:*current-tx* tx)
           (bl.interop:*current-spent-utxos* spent)
           (bl.interop:*current-input-index* 0)
           (bl.interop:*precomputed-sighash*
             (bl.interop:init-precomputed-sighash tx spent))
           (sig (bl.crypto:sign-schnorr
                 tweaked (bl.interop:compute-bip341-sighash
                          (bl.store:utxo-entry-value utxo) 0 nil nil))))
      (setf (bl.ser:transaction-witness tx) (vector (list sig)))
      (is-true (bl.val:validate-input-script tx 0 utxo)))))
