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

;;;; --- Core's [category:level] prefix (BCLog::LogPrefix) ---

(test log-prefix-matches-core-for-every-shape
  "Core's LogPrefix (logging.cpp:343-367) decides the tag on every log line,
and the functional tests match on the rendered result — feature_config_args.py
looks for the literal '[warning] Parsed potentially confusing double-negative'.

The uncategorized-INFO case is the one that changes most lines: Core prints NO
tag there, where this used to print `INFO: `."
  (flet ((p (cat level) (bitcoin-lisp::log-category-level-prefix cat level)))
    (is (string= "" (p nil :info))
        "an uncategorized info line carries no tag in Core")
    (is (string= "[warning] " (p nil :warn)))
    (is (string= "[error] " (p nil :error)))
    (is (string= "[debug] " (p nil :debug)))
    ;; A category implies debug, so Core prints the category alone.
    (is (string= "[net] " (p "net" :debug)))
    (is (string= "[net:warning] " (p "net" :warn)))
    (is (string= "[net:error] " (p "net" :error)))
    ;; "all" is Core's LogFlags::ALL, which is the no-category case.
    (is (string= "" (p "all" :info)))
    (is (string= "[warning] " (p "all" :warn)))))

(test log-level-names-are-cores-spelling
  ":WARN prints as \"warning\". Core's LogLevelToStr has no \"warn\", and a
test matching Core's word would never fire on ours."
  (is (string= "warning" (bitcoin-lisp::log-level-name :warn)))
  (is (string= "error" (bitcoin-lisp::log-level-name :error)))
  (is (string= "info" (bitcoin-lisp::log-level-name :info)))
  (is (string= "debug" (bitcoin-lisp::log-level-name :debug)))
  (is (string= "trace" (bitcoin-lisp::log-level-name :trace))))

(test log-entry-renders-the-prefix
  "The whole line, not just the prefix helper: a warning must contain Core's
tag immediately before the message, and an info line must have no tag between
the timestamp and the message."
  (let ((warn (bitcoin-lisp::format-log-entry :warn "hello ~A" '("world")))
        (info (bitcoin-lisp::format-log-entry :info "hello ~A" '("world")))
        (net (bitcoin-lisp::format-log-entry :debug "hello ~A" '("world") "net")))
    (is-true (search "[warning] hello world" warn))
    (is-true (search "] hello world" info))
    (is-false (search "[warning]" info))
    (is-false (search "INFO:" info))
    (is-true (search "[net] hello world" net))))

(test log-cat-tags-the-line-with-its-category
  "log-cat's category used to be consulted for the enabled/disabled decision
and then DROPPED, so every categorized line came out as an untagged debug line
— there was no way to tell from the log which subsystem wrote it."
  (let ((bitcoin-lisp::*current-log-level* :debug)
        (bitcoin-lisp::*log-file-stream* nil))
    (bitcoin-lisp:log-cat "net" "a categorized line")
    (let ((entry (find-if (lambda (e) (and e (search "a categorized line" e)))
                          bitcoin-lisp::*log-buffer*)))
      (is-true entry "the line reached the buffer")
      (when entry
        (is-true (search "[net] a categorized line" entry))))))
