(in-package #:bitcoin-lisp.networking)

;;;; The protocol's specials that layers loading before it read
;;;;
;;;; src/networking/'s protocol files (peer, protocol, headers-sync, ibd) load
;;;; after validation and the node struct, and both of those read the IBD
;;;; latch below. Defining it here, right after config.lisp's node globals,
;;;; lets them name it at compile time.

(defvar *cached-is-ibd* t
  "Latched IBD status: starts true; initial-block-download-p latches it
to false once the tip has enough work and is recent, and it never flips
back for the life of the node (Core m_cached_is_ibd, validation.h:1049,
latched by UpdateIBDStatus, validation.cpp:3314-3322). Re-set to T by
reset-ibd-stop at node start.")
