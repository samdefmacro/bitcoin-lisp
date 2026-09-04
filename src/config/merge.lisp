(in-package #:bitcoin-lisp.config)

;;;; Merging the sources (Core common/settings.cpp)
;;;
;;; One option name can be set on the command line, in settings.json and in
;;; either section of any bitcoin.conf. Core resolves that per NAME, not per
;;; cell: GetSetting for a scalar option and GetSettingsList for a repeatable
;;; one, both walking the sources in precedence order and both STOPPING at a
;;; negation. Appending the sources into one alist and letting ASSOC pick gets
;;; the precedence right and the negations wrong -- `-norpcauth` used to arrive
;;; as one more element of the list, the string "0".
;;;
;;; A settings ROW is (name string-value json), as CLI-SETTINGS-ROWS,
;;; CONF-SETTINGS-ROWS and SETTINGS-CONFIG-ROWS produce it. JSON is the value
;;; Core stored (SettingsValue::write()), which is the only place a negation is
;;; visible: `-noconnect` and `connect=0` both read "0" to an option reader,
;;; and only the first is Core's JSON `false`.

(defun setting-row-negated-p (row)
  "T when ROW is Core's JSON `false` — a NEGATION (`-nofoo`, InterpretValue,
common/args.cpp:105-121). Nothing else counts: an ordinary value of \"0\" is a
value, which is why `-connect=0` is not a negation."
  (string= (third row) "false"))

;;; --- One source's span for one name (Core SettingsSpan, settings.h:86-104) ---

(defun %span-values (rows)
  "The span's values, Core SettingsSpan::begin() = data + negated()
(settings.cpp:264-274): every value up to and INCLUDING the last negation is
dropped, so a negation erases what came before it in the same source."
  (let ((last (position-if #'setting-row-negated-p rows :from-end t)))
    (if last (nthcdr (1+ last) rows) rows)))

(defun %span-negated-p (rows)
  "Core SettingsSpan::negated() > 0: the span holds a negation anywhere."
  (some #'setting-row-negated-p rows))

(defun %span-last-negated-p (rows)
  "Core SettingsSpan::last_negated(): the span's LAST value is a negation, so
it has nothing left to offer and lower-precedence sources are blocked."
  (and rows (setting-row-negated-p (car (last rows)))))

(defun %config-file-source-p (kind)
  "True for the two bitcoin.conf sources. They differ from the command line in
both directions Core cares about: the FIRST value of a config-file span wins
rather than the last (settings.cpp:165-169), and their values come back from
the dead after a negation that left the list empty (:210-217)."
  (member kind '(:network-section :default-section)))

;;; --- The two readers (Core GetSetting / GetSettingsList) ---

(defun merge-setting (spans)
  "Core GetSetting (settings.cpp:145-199) over SPANS, a list of (kind . rows)
in precedence order. Returns (VALUES row negated-p): ROW is the winning row, or
NIL when no source set the option or a negation won, and NEGATED-P is Core's
IsArgNegated (args.cpp:456, GetSetting().isFalse())."
  (dolist (span spans (values nil nil))
    (destructuring-bind (kind . rows) span
      (cond ((%span-last-negated-p rows) (return (values nil t)))
            (rows (return (values (if (%config-file-source-p kind)
                                      (first (%span-values rows))
                                      (car (last rows)))
                                  nil)))))))

(defun merge-settings-list (spans)
  "Core GetSettingsList (settings.cpp:203-246) over SPANS, a list of
 (kind . rows) in precedence order. Returns the surviving rows, in source
order: every occurrence of a repeatable option counts, a negation erases the
values before it AND blocks every lower-precedence source, and a negation that
leaves the list empty also suppresses the config file's \"zombie\" values."
  (let ((result nil) (done nil) (prev-negated-empty nil))
    (dolist (span spans (nreverse result))
      (destructuring-bind (kind . rows) span
        (when (or (not done)
                  (and (%config-file-source-p kind) (not prev-negated-empty)))
          (dolist (row (%span-values rows)) (push row result)))
        (when (%span-negated-p rows) (setf done t))
        (when (and (%span-last-negated-p rows) (null result))
          (setf prev-negated-empty t))))))

;;; --- The merged alist the node reads ---

(defun %name-spans (sources name)
  "The (kind . rows) spans SOURCES hold for NAME, in precedence order — Core
MergeSettings' callback sequence (settings.cpp:39-67). A source that never
mentions NAME contributes no span, exactly as its map lookup would miss."
  (loop for (kind . rows) in sources
        for span = (remove-if-not (lambda (row) (string= (first row) name)) rows)
        when span collect (cons kind span)))

(defun %source-names (sources)
  "Every name any source mentions, in first-appearance order."
  (remove-duplicates (loop for (nil . rows) in sources
                           append (mapcar #'first rows))
                     :test #'string= :from-end t))

(defun merged-config-alist (sources)
  "The merged (name . value) alist the node reads, and as a second value the
names Core's IsArgNegated answers T for.

SOURCES are (kind . rows) in Core's precedence order — :COMMAND-LINE,
:SETTINGS, :NETWORK-SECTION, :DEFAULT-SECTION (settings.cpp:34-36). Every name
is resolved on its own, by the reader Core uses for it: GetSettingsList for a
repeatable option, where each surviving occurrence becomes a cell, and
GetSetting for a scalar, which contributes at most one.

So a name's cells are contiguous and an ASSOC still gives the winning value,
which is how every reader of this alist already asks. What changed is that a
negation now erases a repeatable option's span instead of joining it: Core
answers `-rpcauth=a -rpcauth=b -norpcauth` with an EMPTY list, where we
answered (\"a\" \"b\" \"0\") and that \"0\" then failed every consumer that
parsed it."
  (let ((out nil) (negated nil))
    (dolist (name (%source-names sources) (values (nreverse out) (nreverse negated)))
      (let ((spans (%name-spans sources name)))
        ;; IsArgNegated is GetSetting().isFalse() for every option, repeatable
        ;; or not, so the scalar read runs either way.
        (multiple-value-bind (row negated-p) (merge-setting spans)
          (when negated-p (push name negated))
          (if (config-option-repeatable-p name)
              (dolist (kept (merge-settings-list spans))
                (push (cons name (second kept)) out))
              (cond (negated-p (push (cons name "0") out))
                    (row (push (cons name (second row)) out)))))))))
