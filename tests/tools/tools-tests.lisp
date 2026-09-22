(in-package #:bitcoin-lisp.tests)

(def-suite :tools-tests
  :description "Core's side tools: bitcoin-util, bitcoin-tx (Core's own
bitcoin-util-test.json corpus, replayed in-process) and bitcoin-wallet"
  :in :bitcoin-lisp-tests)

(in-suite :tools-tests)

;;; --- Core's bitcoin-util-test.json corpus ------------------------------------
;;;
;;; test/functional/data/util/bitcoin-util-test.json is what tool_utils.py
;;; replays against the real executables: for each vector the arguments, an
;;; optional stdin file, the expected stdout file (compared as TEXT -- its
;;; "Output formatting mismatch" arm -- as well as parsed), the exit code and
;;; a substring of stderr. This lane runs the same vectors through
;;; RUN-BITCOIN-TX / RUN-BITCOIN-UTIL in the image; tool_utils.py remains the
;;; end-to-end check of the executable itself.

(defparameter *tool-corpus-dir*
  (asdf:system-relative-pathname "bitcoin-lisp" "refs/bitcoin/test/functional/data/util/"))

(defun %tool-corpus ()
  "The corpus vectors as alists, in file order."
  (let ((yason:*parse-object-as* :alist))
    (with-open-file (in (merge-pathnames "bitcoin-util-test.json" *tool-corpus-dir*))
      (yason:parse in))))

(defun %vector-field (vector name)
  (cdr (assoc name vector :test #'string=)))

(defun %run-tool-vector (vector)
  "Run one corpus VECTOR. Returns (values stdout stderr exit-code)."
  (let* ((input (%vector-field vector "input"))
         (stdin (make-string-input-stream
                 (if input
                     (uiop:read-file-string (merge-pathnames input *tool-corpus-dir*))
                     "")))
         (out (make-string-output-stream))
         (err (make-string-output-stream))
         (args (%vector-field vector "args"))
         (rc (if (string= (%vector-field vector "exec") "./bitcoin-util")
                 (bl.tools:run-bitcoin-util args :out out :err err)
                 (bl.tools:run-bitcoin-tx args :stdin stdin :out out :err err))))
    (values (get-output-stream-string out) (get-output-stream-string err) rc)))

(defun %tool-vector-failure (vector)
  "NIL when VECTOR's run matches tool_utils.py's four checks, else why not."
  (multiple-value-bind (stdout stderr rc) (%run-tool-vector vector)
    (let ((expected-file (%vector-field vector "output_cmp"))
          (want-rc (or (%vector-field vector "return_code") 0))
          (want-error (%vector-field vector "error_txt")))
      (cond
        ((and expected-file
              (string/= stdout (uiop:read-file-string
                                (merge-pathnames expected-file *tool-corpus-dir*))))
         (format nil "stdout differs from ~A:~%~A" expected-file stdout))
        ((/= rc want-rc)
         (format nil "exit code ~D, want ~D; stderr ~S" rc want-rc stderr))
        ((and want-error (not (search want-error stderr)))
         (format nil "stderr ~S does not contain ~S" stderr want-error))
        ((and (not want-error) (plusp (length stderr)))
         (format nil "unexpected stderr ~S" stderr))))))

(test bitcoin-tx-and-util-match-cores-corpus
  "Every vector of Core's bitcoin-util-test.json gives Core's stdout (byte for
byte), exit code and error text (tool_utils.py:35-115)."
  (let ((corpus (%tool-corpus)))
    (is (= 107 (length corpus))
        "the corpus is 107 vectors, not ~D -- refs/bitcoin moved?" (length corpus))
    (let ((failures (loop for vector in corpus
                          for i from 0
                          for why = (%tool-vector-failure vector)
                          when why
                            collect (format nil "[~D] ~A: ~A" i
                                            (%vector-field vector "description") why))))
      (is (null failures) "~D corpus vector~:P fail:~%~{~A~%~}"
          (length failures) failures))))

;;; --- The pieces, each against Core's own spelling ---------------------------

(test univalue-write-breaks-an-empty-array-over-two-lines
  "UniValue::write(4) (univalue_write.cpp): members at four spaces a level,
and an EMPTY array still opens and closes on separate lines -- the shape of a
transaction with no inputs in every -json vector of the corpus."
  (is (string= (format nil "{~%    \"vin\": [~%    ],~%    \"n\": 1~%}")
               (bl.tools:univalue-write '(("vin" . #()) ("n" . 1)) 4)))
  (is (string= "[\"a\\u001fb\",true,null]"
               (bl.tools:univalue-write (list (format nil "a~Cb" (code-char 31)) t nil)))))

(test parse-script-asm-is-cores-parsescript
  "Core ParseScript (core_io.cpp:95-130): numbers are push_int64, 0x words
are raw bytes, opcodes are read with or without OP_."
  (is (equalp #(#x00 #x51 #x4f #x01 #x11 #x75 #x75 #xab #xcd)
              (bl.tools:parse-script-asm "0 1 -1 17 DROP OP_DROP 0xabcd")))
  (is (equalp #(#x05 #xff #xff #xff #xff #x00)
              (bl.tools:parse-script-asm "4294967295")))
  (signals error (bl.tools:parse-script-asm "4294967296"))
  (signals error (bl.tools:parse-script-asm "OP_NOTANOPCODE")))

(test bitcoin-util-grind-meets-the-headers-own-target
  "Core Grind (bitcoin-util.cpp:112-150): the nonce it writes makes the
header's hash meet the header's own nBits, and nothing else changes."
  (let* ((header (make-array 80 :element-type '(unsigned-byte 8) :initial-element 7))
         (out (make-string-output-stream)))
    ;; nBits 0x1f7fffff: a target of about 2^254, so a few tries suffice.
    (replace header #(#xff #xff #x7f #x1f) :start1 72)
    (is (= 0 (bl.tools:run-bitcoin-util (list "grind" (bl.crypto:bytes-to-hex header))
                                        :out out :err (make-broadcast-stream))))
    (let* ((ground (bl.crypto:hex-to-bytes
                    (string-trim '(#\Newline) (get-output-stream-string out))))
           (hash (bl.crypto:hash256 ground)))
      (is (equalp (subseq header 0 76) (subseq ground 0 76)))
      ;; The most significant byte of the hash is at index 31.
      (is (<= (aref hash 31) #x7f)))))

(test tools-are-chosen-by-program-name
  "The executable is a side tool exactly when argv[0]'s file name is one."
  (is (eq #'bl.tools:run-bitcoin-tx (bl.tools:tool-for-program-name "/x/build/bin/bitcoin-tx")))
  (is (eq #'bl.tools:run-bitcoin-util (bl.tools:tool-for-program-name "bitcoin-util.exe")))
  (is (null (bl.tools:tool-for-program-name "/x/build/bin/bitcoind"))))
