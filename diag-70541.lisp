;; Diagnostic: find producer of prevout a413b67ad805...:4 referenced by
;; block 70541 tx-1. Scan blocks h=70000..70540 (forensic raw payloads
;; for the failing zone, plus on-disk legacy blocks). Report which
;; height contains a tx with that txid.

(asdf:load-system :bitcoin-lisp)
(setf bitcoin-lisp:*network* :testnet4)

(in-package :cl-user)

(defvar *target-txid-hex*
  "a413b67ad8057d9782fb1922df43cc78b1344b818b786b6df3128862c9074c65")

(defvar *data-dir* #P"/data/bitcoin-lisp/data/testnet4/testnet4/")
(defvar *forensic-dir* #P"/data/bitcoin-lisp/forensic-blocks/")

(defun hex (b) (bitcoin-lisp.crypto:bytes-to-hex b))

(defun load-state ()
  (let ((cs (bitcoin-lisp.storage:init-chain-state *data-dir*)))
    (bitcoin-lisp.storage:load-state cs)
    (bitcoin-lisp.storage:load-header-index cs)
    cs))

(defun raw-block (hash-hex)
  "Try forensic dir first; fall back to .blk in blocks/ (legacy format)."
  (let ((forensic (merge-pathnames
                   (make-pathname :name hash-hex :type "raw") *forensic-dir*))
        (legacy (merge-pathnames
                 (make-pathname :name hash-hex :type "blk")
                 (merge-pathnames "blocks/" *data-dir*))))
    (cond
      ((probe-file forensic)
       (with-open-file (in forensic :direction :input :element-type '(unsigned-byte 8))
         (let ((b (make-array (file-length in) :element-type '(unsigned-byte 8))))
           (read-sequence b in) b)))
      ((probe-file legacy)
       (with-open-file (in legacy :direction :input :element-type '(unsigned-byte 8))
         (let ((b (make-array (file-length in) :element-type '(unsigned-byte 8))))
           (read-sequence b in) b))))))

(defun heights->hashes (cs from-h to-h)
  (let ((tbl (make-hash-table :test 'eql)))
    (maphash (lambda (hash entry)
               (let ((h (bitcoin-lisp.storage:block-index-entry-height entry)))
                 (when (and (<= from-h h) (<= h to-h))
                   (setf (gethash h tbl) hash))))
             (bitcoin-lisp.storage::chain-state-block-index cs))
    tbl))

(defun search-for-txid (cs target-bytes from-h to-h)
  (let ((heights (heights->hashes cs from-h to-h)))
    (loop for h from from-h to to-h
          for hash = (gethash h heights)
          for hash-hex = (and hash (hex hash))
          for raw = (and hash-hex (raw-block hash-hex))
          when raw
            do (handler-case
                   (let ((blk (bitcoin-lisp.serialization:parse-block-payload raw)))
                     (loop for tx in (bitcoin-lisp.serialization:bitcoin-block-transactions blk)
                           for tx-idx from 0
                           for txid = (bitcoin-lisp.serialization:transaction-hash tx)
                           when (equalp txid target-bytes)
                             do (format t "~%FOUND: height=~D tx-idx=~D block=~A~%"
                                        h tx-idx hash-hex)
                                (format t "  tx outputs:~%")
                                (loop for out in (bitcoin-lisp.serialization:transaction-outputs tx)
                                      for i from 0
                                      do (format t "    [~D] value=~D script=~A~%"
                                                 i
                                                 (bitcoin-lisp.serialization:tx-out-value out)
                                                 (hex (bitcoin-lisp.serialization:tx-out-script-pubkey out))))
                                (return-from search-for-txid (values h tx-idx hash-hex))))
                 (error (e) (format t "  h=~D parse-error: ~A~%" h e))))
    nil))

(let* ((cs (load-state))
       (target (bitcoin-lisp.crypto:hex-to-bytes *target-txid-hex*)))
  (format t "~%searching for txid ~A~%" *target-txid-hex*)
  (format t "best-height=~D~%"
          (bitcoin-lisp.storage:current-height cs))
  (let ((result (search-for-txid cs target 70000 70540)))
    (unless result
      (format t "~%NOT FOUND in 70000-70540. Trying full range 0-70540...~%")
      (search-for-txid cs target 0 70540))))

;; Now check whether the saved UTXO set has (a413b67a..., 4).
(format t "~%--- UTXO set lookup for the four outputs of producer tx ---~%")
(let ((utxo (bitcoin-lisp.storage:make-utxo-set))
      (target (bitcoin-lisp.crypto:hex-to-bytes *target-txid-hex*)))
  (bitcoin-lisp.storage:load-utxo-set
   utxo (bitcoin-lisp.storage:utxo-set-file-path *data-dir*))
  (format t "  utxo-count=~D~%" (bitcoin-lisp.storage:utxo-count utxo))
  (loop for i from 0 to 4
        for entry = (bitcoin-lisp.storage:get-utxo utxo target i)
        do (format t "  vout=~D ~A~%" i
                   (if entry
                       (format nil "value=~D height=~D"
                               (bitcoin-lisp.storage:utxo-entry-value entry)
                               (bitcoin-lisp.storage:utxo-entry-height entry))
                       "MISSING"))))

(sb-ext:exit :code 0)
