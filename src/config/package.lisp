;;;; Package bitcoin-lisp.config -- the public API of src/config/.
;;;;
;;;; First component of the bitcoin-lisp/config sub-system (bitcoin-lisp.asd):
;;;; the option registry (DEFINE-OPTION) and the parsers for the command
;;;; line, bitcoin.conf, settings.json and option values. It knows no
;;;; chain: the option TABLE (src/config-options.lisp) and the specials it
;;;; sets live in the main system, which :USEs this package and re-exports
;;;; the names its callers and tests always reached as bl:. Add an export
;;;; here when a definition in src/config/ becomes API; keep %-prefixed
;;;; names internal.

(defpackage #:bitcoin-lisp.config
  (:documentation "The option registry and the configuration parsers (Core
common/args.cpp, common/config.cpp, common/settings.cpp). src/config/.")
  (:use #:cl #:bitcoin-lisp.conditions)
  (:export
   #:config-option
   #:make-config-option
   #:config-option-p
   #:config-option-name
   #:config-option-key
   #:config-option-type
   #:config-option-min
   #:config-option-collect
   #:config-option-repeatable
   #:config-option-kind
   #:config-option-network-only
   #:config-option-sensitive
   #:config-option-global
   #:config-option-apply
   #:config-option-core
   #:option-definition-error-name
   #:option-definition-error-detail
   #:*config-options*
   #:register-config-option
   #:option-definition-error
   #:define-option
   #:define-core-only-options
   #:find-config-option
   #:config-option-repeatable-p
   #:core-only-option-p
   #:sensitive-config-option-p
   #:scalar-key-options
   #:collected-key-options
   #:global-options
   #:parse-option-value
   #:apply-option-globals
   #:locale-independent-atoi
   #:conf-parse-bool
   #:conf-parse-int
   #:log-categories-string
   #:parse-loglevel-spec
   #:conf-parse-loglevel-global
   #:conf-parse-loglevel
   #:conf-parse-money
   #:conf-parse-user-hex
   #:+max-subversion-length+
   #:ua-comment-safe-p
   #:+default-proxy-port+
   #:conf-parse-proxy
   #:conf-parse-byte-units
   #:conf-parse-network-name
   #:conf-section-name
   #:parse-bind-option
   #:conf-effective-listen-flags
   #:split-option-token
   #:interpret-arg
   #:cli-settings-rows
   #:parse-cli-args
   #:supplied-core-only-options
   #:known-config-option-p
   #:cli-parse-error
   #:cli-parse-error-detail
   #:check-cli-args
   #:cli-arg-log-cells
   #:config-parse-error
   #:config-parse-error-message
   #:conf-settings-rows
   #:parse-bitcoin-conf-sections
   #:parse-bitcoin-conf
   #:conf-global-entries
   #:resolve-network-from-config
   #:unknown-config-file-keys
   #:config-arg-log-cells
   #:+settings-warning-key+
   #:+client-name+
   #:settings-file-warning
   #:render-json-value
   #:parse-settings-json
   #:render-settings-json
   #:settings-config-rows
   #:validate-settings-values
   #:unknown-settings-keys
   #:setting-row-negated-p
   #:merge-setting
   #:merge-settings-list
   #:network-only-option-p
   #:use-default-section-p
   #:unsuitable-section-only-options
   #:merged-config-alist))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
