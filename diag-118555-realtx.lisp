;;; Real-tx reproducer for h=118555 SE-VerifyFailed @ OP_CHECKMULTISIGVERIFY.
;;;
;;; Loads forensic raw payload of block 118555, finds tx-idx=3 input-idx=1,
;;; binds *current-tx* + *current-input-index*, fakes the spent UTXO
;;; (scriptpubkey from the SCRIPT-FAILED log line), and runs validation
;;; with *debug-checksig* = T. Each checksig call dumps:
;;;   subscript-for-hash (post FindAndDelete)
;;;   sighash (32 bytes)
;;;   der-sig + sighash-type
;;;   pubkey
;;; Compare those against an external sighash oracle (Bitcoin Core or
;;; python-bitcoinlib) to find the byte-level divergence.
;;;
;;; Run on the server where the .raw forensic capture lives:
;;;   /data/bitcoin-lisp/forensic-blocks/<hash>.raw
;;; The hash for h=118555 is set below; update if forensic capture
;;; lands a different hash.

(asdf:load-system :bitcoin-lisp)

(defpackage #:diag-118555-realtx (:use :cl))
(in-package #:diag-118555-realtx)

(defparameter *forensic-dir* "/data/bitcoin-lisp/forensic-blocks/")

;; SET THIS to the hash of testnet4 block 118555 once forensic capture lands.
;; You can derive it from chainstate (headerindex) or from the SCRIPT-FAILED
;; log: prev-txid is in the log but the block hash is not — easiest is to
;; ls -t /data/bitcoin-lisp/forensic-blocks/ and pick the most recent one
;; written around the time of the SCRIPT-FAILED, or load chain-state and
;; walk by height.
(defparameter *block-118555-hash* nil
  "32-byte hash of block 118555 (hex), or NIL to auto-discover from chain-state.")

(defparameter *prev-scriptpubkey-hex-path* "/tmp/118555-spk.hex"
  "ScriptPubKey of the prev output being spent by tx-3 input-1.")

(defun read-hex-file (path)
  (let ((s (with-open-file (in path :direction :input)
             (with-output-to-string (out)
               (loop for line = (read-line in nil nil)
                     while line do (write-string line out))))))
    (bitcoin-lisp.crypto:hex-to-bytes
     (string-trim '(#\Space #\Newline #\Tab) s))))

(defun read-raw-block (hash-hex)
  (let ((path (format nil "~A~A.raw" *forensic-dir* hash-hex)))
    (unless (probe-file path)
      (error "Forensic raw block missing: ~A" path))
    (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
      (let ((buf (make-array (file-length in) :element-type '(unsigned-byte 8))))
        (read-sequence buf in)
        buf))))

(defun find-block-hash-for-height (target-height)
  "Walk header index, return hash of block at TARGET-HEIGHT (a hex string)."
  (let* ((data-dir #P"/data/bitcoin-lisp/data/testnet4/testnet4/")
         (cs (bitcoin-lisp.storage:init-chain-state data-dir)))
    (bitcoin-lisp.storage:load-state cs)
    (bitcoin-lisp.storage:load-header-index cs)
    (let ((found nil))
      (maphash (lambda (hash entry)
                 (when (= (bitcoin-lisp.storage:block-index-entry-height entry)
                          target-height)
                   (setf found hash)))
               (bitcoin-lisp.storage::chain-state-block-index cs))
      (when found
        (bitcoin-lisp.crypto:bytes-to-hex found)))))

(defun run ()
  (let* ((hash-hex (or *block-118555-hash* (find-block-hash-for-height 118555))))
    (unless hash-hex
      (error "no block-index entry at h=118555 — header sync hasn't reached it"))
    (format t "block 118555 hash: ~A~%" hash-hex)
    (let* ((raw-block (read-raw-block hash-hex))
           (block (bitcoin-lisp.serialization:parse-block-payload raw-block))
           (txs (bitcoin-lisp.serialization:bitcoin-block-transactions block))
           (tx (nth 3 txs))
           (input-idx 1)
           (input (nth input-idx (bitcoin-lisp.serialization:transaction-inputs tx)))
           (scriptsig (bitcoin-lisp.serialization:tx-in-script-sig input))
           (prev-spk (read-hex-file *prev-scriptpubkey-hex-path*))
           (script-flags
             "P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY,TAPROOT"))
      (format t "tx 3 has ~D inputs, ~D outputs~%"
              (length (bitcoin-lisp.serialization:transaction-inputs tx))
              (length (bitcoin-lisp.serialization:transaction-outputs tx)))
      (format t "input ~D scriptsig len: ~D bytes~%" input-idx (length scriptsig))
      (format t "prev scriptpubkey len: ~D bytes~%" (length prev-spk))
      (format t "tx version: ~D, locktime: ~D~%"
              (bitcoin-lisp.serialization:transaction-version tx)
              (bitcoin-lisp.serialization:transaction-lock-time tx))
      ;; Dump raw transaction bytes (witness-stripped legacy serialization, since
      ;; this input is non-witness anyway). For Python sighash oracle.
      (let ((tx-bytes (bitcoin-lisp.serialization:serialize-transaction tx)))
        (format t "tx bytes len=~D~%  hex=~A~%"
                (length tx-bytes)
                (bitcoin-lisp.crypto:bytes-to-hex tx-bytes)))
      (loop for in in (bitcoin-lisp.serialization:transaction-inputs tx)
            for i from 0
            do (let ((p (bitcoin-lisp.serialization:tx-in-previous-output in)))
                 (format t "  input[~D]: outpoint=~A:~D scriptsig-len=~D sequence=~X~%"
                         i
                         (bitcoin-lisp.crypto:bytes-to-hex
                          (bitcoin-lisp.serialization:outpoint-hash p))
                         (bitcoin-lisp.serialization:outpoint-index p)
                         (length (bitcoin-lisp.serialization:tx-in-script-sig in))
                         (bitcoin-lisp.serialization:tx-in-sequence in))))
      (loop for out in (bitcoin-lisp.serialization:transaction-outputs tx)
            for i from 0
            do (format t "  output[~D]: value=~D scriptpubkey-len=~D~%"
                       i
                       (bitcoin-lisp.serialization:tx-out-value out)
                       (length (bitcoin-lisp.serialization:tx-out-script-pubkey out))))
      (format t "~%=== running validation with *debug-checksig* = T ===~%")
      (let ((bitcoin-lisp.coalton.interop:*current-tx* tx)
            (bitcoin-lisp.coalton.interop:*current-input-index* input-idx)
            (bitcoin-lisp.coalton.interop:*script-flags* script-flags)
            (bitcoin-lisp.coalton.interop::*debug-checksig* t)
            (bitcoin-lisp.coalton.interop::*script-fail-trace* t))
        (multiple-value-bind (ok err)
            (bitcoin-lisp.coalton.interop:run-scripts-with-p2sh scriptsig prev-spk t)
          (format t "~%=> ok=~A err=~A~%" ok err))))))

(run)
