(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/script_descriptor_cache.cpp at the pin: DescriptorCache
;;;; under any sequence of parent and derived xpub caches -- a cached xpub is
;;;; fetched back unchanged. Ours is BL.RPC's DESCRIPTOR-CACHE, which the
;;;; wallet persists as walletdescriptorcache records. Core's target does not
;;;; exercise MergeAndDiff (descriptor.cpp), which the wallet runs on every
;;;; top-up to learn what to write; ours also merges each step into a second
;;;; cache: the diff is exactly what was new, a repeat merges to nothing.

(def-suite :fuzz-script-descriptor-cache-tests :in :bitcoin-lisp-tests
  :description "Core fuzz script_descriptor_cache.cpp")

(in-suite :fuzz-script-descriptor-cache-tests)

(defun %xpub-from-code (code)
  "CExtPubKey::Decode of a 74-byte BIP32 payload: depth, parent fingerprint,
child number (big-endian), chain code, compressed key."
  (flet ((be (start end) (loop for i from start below end sum (ash (aref code i) (* 8 (- end i 1))))))
    (bl.crypto:make-ext-key :depth (aref code 0) :parent-fingerprint (be 1 5) :child-number (be 5 9)
                            :chain-code (subseq code 9 41) :key (subseq code 41 74))))

(defun %cache-count (cache)
  (+ (hash-table-count (bl.rpc:descriptor-cache-parent-xpubs cache))
     (loop for inner being the hash-values of (bl.rpc:descriptor-cache-derived-xpubs cache)
           sum (hash-table-count inner))))

(define-fuzz-target script-descriptor-cache
    (buffer :core "script_descriptor_cache.cpp:18-44" :iterations 1500 :max-len 800)
  "A cached parent or derived xpub is fetched back unchanged, and merging the
cache into another yields as the diff exactly the entries that were new."
  (let ((fdp (make-fuzzed-data-provider buffer))
        (cache (bl.rpc:make-descriptor-cache))
        (merged (bl.rpc:make-descriptor-cache)))
    (limited-while ((consume-bool fdp) 10000)
      (let ((code (consume-bytes fdp 74)))
        (when (= (length code) 74)
          (let ((xpub (%xpub-from-code code))
                (pos (consume-integral fdp :u32)))
            (if (consume-bool fdp)
                (progn (bl.rpc:descriptor-cache-parent cache pos)
                       (setf (bl.rpc:descriptor-cache-parent cache pos) xpub)
                       (fuzz-assert (eq (fuzz-sabotage (bl.rpc:descriptor-cache-parent cache pos)) xpub)
                                    "a cached parent xpub was not fetched back"))
                (let ((der (consume-integral fdp :u32)))
                  (bl.rpc:descriptor-cache-derived cache pos der)
                  (setf (bl.rpc:descriptor-cache-derived cache pos der) xpub)
                  (fuzz-assert (eq (bl.rpc:descriptor-cache-derived cache pos der) xpub)
                               "a cached derived xpub was not fetched back")))))
        (let* ((before (%cache-count merged))
               (diff (handler-case (bl.rpc:descriptor-cache-merge-and-diff merged cache)
                       ;; Core throws on a slot cached twice with different
                       ;; xpubs; a fuzzed cache overwrites its own slots.
                       (error () (setf merged (bl.rpc:make-descriptor-cache)) nil))))
          (when diff
            (fuzz-assert (= (+ before (%cache-count diff)) (%cache-count merged))
                         "the diff does not account for what the merge added")
            (fuzz-assert (zerop (%cache-count (bl.rpc:descriptor-cache-merge-and-diff merged cache)))
                         "a second merge of the same cache found something new")))))))
