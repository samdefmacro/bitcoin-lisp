(in-package #:bitcoin-lisp.tests)

(def-suite :logging-tests
  :description "Log formatting, control-character escaping and rate limiting"
  :in :bitcoin-lisp-tests)

(in-suite :logging-tests)

;;; --- formatting -------------------------------------------------------------

(test log-entry-is-one-line-even-for-a-condition
  "A condition report must not be pretty-printed across the log.

With *PRINT-PRETTY* left on, `~A' of a multi-line object is laid out from the
current column, so a type error appended to a log line becomes ten indented
lines whose first carries only the word `The'. That is how the fd>1023 select()
failure reported itself on mainnet; the guard is the binding in
FORMAT-LOG-ENTRY, so assert against the shape that reproduces it."
  (let ((condition (make-condition 'type-error
                                   :datum 3119
                                   :expected-type '(unsigned-byte 10)))
        (*print-right-margin* 40))
    ;; The symptom, so the test fails if the reproducer stops reproducing.
    (is (find #\Newline (let ((*print-pretty* t))
                          (format nil "prefix: ~A" condition))))
    (let ((entry (bitcoin-lisp::format-log-entry :warn "boom: ~A" (list condition))))
      (is (null (find #\Newline entry)))
      (is (search "3119" entry))
      (is (search "UNSIGNED-BYTE 10" entry)))))

(test log-escapes-control-characters-but-keeps-newline
  "Core BCLog::LogEscapeMessage (logging.cpp:329-340)."
  (is (string= "plain ascii" (bitcoin-lisp::%log-escape-message "plain ascii")))
  ;; Identity, not just equality: an unescaped string is returned as-is.
  (let ((s "nothing to escape"))
    (is (eq s (bitcoin-lisp::%log-escape-message s))))
  (is (string= (format nil "a~%b") (bitcoin-lisp::%log-escape-message (format nil "a~%b"))))
  (is (string= "cr\\x0d esc\\x1b del\\x7f nul\\x00"
               (bitcoin-lisp::%log-escape-message
                (format nil "cr~C esc~C del~C nul~C"
                        #\Return (code-char 27) (code-char 127) (code-char 0)))))
  ;; A peer-supplied subversion string reaches the log, so the carriage return
  ;; that would let it overwrite the line is escaped. A newline is NOT — Core
  ;; passes it through so a genuinely multi-line message stays readable — which
  ;; is why this is escaping and not sanitising.
  (is (string= "peer /Satoshi:1.0/\\x0d[2026-01-01 00:00:00] ERROR: fake"
               (bitcoin-lisp::%log-escape-message
                (format nil "peer /Satoshi:1.0/~C[2026-01-01 00:00:00] ERROR: fake"
                        #\Return)))))

;;; --- rate limiting (Core BCLog::LogRateLimiter) ------------------------------

(defmacro with-fresh-rate-limiter ((&key (limit t)) &body body)
  `(let ((bitcoin-lisp::*log-rate-locations* (make-hash-table :test 'equal))
         (bitcoin-lisp::*log-rate-window-start* (get-universal-time))
         (bitcoin-lisp::*log-suppressions-active* nil)
         (bitcoin-lisp::*log-rate-limit* ,limit)
         (bitcoin-lisp::*log-stream* nil)
         (bitcoin-lisp::*log-file-stream* nil))
     ,@body))

(test log-rate-limiter-state-machine
  "Consume returns Core's three statuses, and the budget is per location."
  (with-fresh-rate-limiter ()
    (is (eq :unsuppressed (bitcoin-lisp::%log-rate-consume "site A" 10)))
    (is (eq :newly-suppressed
            (bitcoin-lisp::%log-rate-consume
             "site A" (* 2 bitcoin-lisp::+log-ratelimit-max-bytes+))))
    (is (eq :still-suppressed (bitcoin-lisp::%log-rate-consume "site A" 10)))
    ;; A different location keeps its own budget — suppressing one site must
    ;; never silence the rest of the node.
    (is (eq :unsuppressed (bitcoin-lisp::%log-rate-consume "site B" 10)))
    (is-true bitcoin-lisp::*log-suppressions-active*)))

(test log-rate-limiter-exhausts-a-budget-gradually
  "The budget is bytes, not calls: many small writes eventually suppress."
  (with-fresh-rate-limiter ()
    (let* ((chunk 1024)
           (calls (ceiling bitcoin-lisp::+log-ratelimit-max-bytes+ chunk))
           (statuses (loop repeat (1+ calls)
                           collect (bitcoin-lisp::%log-rate-consume "site" chunk))))
      (is (every (lambda (s) (eq s :unsuppressed)) (subseq statuses 0 calls)))
      (is (eq :newly-suppressed (car (last statuses)))))))

(test log-rate-limiter-window-reset-restores-and-reports
  "Reset clears the budget and reports what was dropped (Core Reset)."
  (with-fresh-rate-limiter ()
    (bitcoin-lisp::%log-rate-consume
     "noisy site" (* 2 bitcoin-lisp::+log-ratelimit-max-bytes+))
    (is-true bitcoin-lisp::*log-suppressions-active*)
    ;; Backdate the window so the lazy close fires.
    (setf bitcoin-lisp::*log-rate-window-start*
          (- (get-universal-time) bitcoin-lisp::+log-ratelimit-window-seconds+ 1))
    (bitcoin-lisp::%log-maybe-reset-window)
    (is-false bitcoin-lisp::*log-suppressions-active*)
    (is (zerop (hash-table-count bitcoin-lisp::*log-rate-locations*)))
    (let ((restart (find-if (lambda (e) (and e (search "Restarting logging" e)))
                            bitcoin-lisp::*log-buffer*)))
      (is-true restart)
      (is (search "noisy site" restart)))))

(test log-rate-limiter-suppresses-the-file-not-the-console
  "Core: \"Suppressing logging to disk ... Console logging unaffected.\""
  (with-fresh-rate-limiter ()
    (let ((console (make-string-output-stream))
          (file (make-string-output-stream)))
      (let ((bitcoin-lisp::*log-stream* console)
            (bitcoin-lisp::*log-file-stream* file))
        (bitcoin-lisp::%log-emit :info "big ~A" (list (make-string 4096 :initial-element #\x)))
        ;; Blow the budget from the same location, then write again.
        (bitcoin-lisp::%log-rate-consume
         "big ~A" (* 2 bitcoin-lisp::+log-ratelimit-max-bytes+))
        (bitcoin-lisp::%log-emit :info "big ~A" (list "second")))
      (let ((console-text (get-output-stream-string console))
            (file-text (get-output-stream-string file)))
        (is (search "second" console-text))
        (is (null (search "second" file-text)))
        ;; Every line carries Core's suppression marker while one is active.
        (is (search "[*] " console-text))))))

(test log-rate-limiter-never-suppresses-its-own-notices
  "The NEWLY_SUPPRESSED notice is emitted with should_ratelimit=false, so it
cannot be eaten by the limiter that produced it."
  (with-fresh-rate-limiter ()
    (let ((file (make-string-output-stream)))
      (let ((bitcoin-lisp::*log-file-stream* file))
        (bitcoin-lisp::%log-emit
         :info "wordy ~A" (list (make-string (* 2 bitcoin-lisp::+log-ratelimit-max-bytes+)
                                             :initial-element #\y))))
      (let ((text (get-output-stream-string file)))
        (is (search "Excessive logging detected" text))
        ;; Core writes the entry that tripped the limit: "Last log entry."
        (is (search "Last log entry." text))
        (is (search "yyyy" text))))))

(test debug-and-category-logging-are-not-rate-limited
  "Core rate-limits Info and louder only (util/log.h:91-113): -debug users are
assumed to accept the volume."
  (with-fresh-rate-limiter ()
    (let ((bitcoin-lisp::*current-log-level* :debug))
      (bitcoin-lisp::node-log :debug "quiet ~A" "x")
      (bitcoin-lisp::node-log-category "validation" "cat ~A" "x"))
    (is (zerop (hash-table-count bitcoin-lisp::*log-rate-locations*)))
    (bitcoin-lisp::node-log :warn "loud ~A" "x")
    (is (= 1 (hash-table-count bitcoin-lisp::*log-rate-locations*)))))

(test log-rate-limit-can-be-turned-off
  "-logratelimit=0 (Core -logratelimit)."
  (with-fresh-rate-limiter (:limit nil)
    (let ((file (make-string-output-stream)))
      (let ((bitcoin-lisp::*log-file-stream* file))
        (dotimes (i 3)
          (bitcoin-lisp::%log-emit
           :info "huge ~A" (list (make-string bitcoin-lisp::+log-ratelimit-max-bytes+
                                              :initial-element #\z)))))
      (is (null (search "Excessive logging detected" (get-output-stream-string file)))))
    (is (zerop (hash-table-count bitcoin-lisp::*log-rate-locations*)))))
