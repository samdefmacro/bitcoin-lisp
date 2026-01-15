;;;; Core Bitcoin types with static type safety
;;;;
;;;; This module defines domain-specific newtypes that provide compile-time
;;;; guarantees about type safety. Mixing Hash256 and Hash160, or treating
;;;; a Satoshi value as a raw integer, will result in compile-time errors.

(in-package #:bitcoin-lisp.coalton.types)

(named-readtables:in-readtable coalton:coalton)

(coalton-toplevel

  ;;;; Hash256 - 32-byte double-SHA256 hash
  ;;;;
  ;;;; Used for: block hashes, transaction hashes, merkle roots

  (define-type Hash256
    "A 32-byte hash (double SHA-256).
     Used for block hashes, transaction IDs, and merkle roots."
    (Hash256 (Vector U8)))

  (declare make-hash256 ((Vector U8) -> (Result String Hash256)))
  (define (make-hash256 bytes)
    "Create a Hash256 from a 32-byte vector. Returns Err if length is not 32."
    (if (== (the UFix (coalton-library/vector:length bytes)) 32)
        (Ok (Hash256 bytes))
        (Err "Hash256 requires exactly 32 bytes")))

  (declare hash256-bytes (Hash256 -> (Vector U8)))
  (define (hash256-bytes h)
    "Extract the underlying bytes from a Hash256."
    (match h
      ((Hash256 bytes) bytes)))

  (declare hash256-zero (Unit -> Hash256))
  (define (hash256-zero)
    "Return a zero-filled Hash256 (32 zero bytes)."
    (Hash256 (lisp (Vector U8) ()
               (cl:coerce (cl:make-list 32 :initial-element 0) 'cl:vector))))

  ;;;; Hash160 - 20-byte RIPEMD160(SHA256(x)) hash
  ;;;;
  ;;;; Used for: public key hashes, script hashes (P2PKH, P2SH addresses)

  (define-type Hash160
    "A 20-byte hash (RIPEMD160(SHA256)).
     Used for public key hashes and script hashes."
    (Hash160 (Vector U8)))

  (declare make-hash160 ((Vector U8) -> (Result String Hash160)))
  (define (make-hash160 bytes)
    "Create a Hash160 from a 20-byte vector. Returns Err if length is not 20."
    (if (== (the UFix (coalton-library/vector:length bytes)) 20)
        (Ok (Hash160 bytes))
        (Err "Hash160 requires exactly 20 bytes")))

  (declare hash160-bytes (Hash160 -> (Vector U8)))
  (define (hash160-bytes h)
    "Extract the underlying bytes from a Hash160."
    (match h
      ((Hash160 bytes) bytes)))

  (declare hash160-zero (Unit -> Hash160))
  (define (hash160-zero)
    "Return a zero-filled Hash160 (20 zero bytes)."
    (Hash160 (lisp (Vector U8) ()
               (cl:coerce (cl:make-list 20 :initial-element 0) 'cl:vector))))

  ;;;; Satoshi - Bitcoin amount in satoshis
  ;;;;
  ;;;; 1 BTC = 100,000,000 satoshis
  ;;;; Using Integer to support the full range (up to 21 million BTC)

  (define-type Satoshi
    "A Bitcoin amount in satoshis.
     1 BTC = 100,000,000 satoshis. Max supply is 2,100,000,000,000,000 satoshis."
    (Satoshi Integer))

  (declare make-satoshi (Integer -> Satoshi))
  (define (make-satoshi value)
    "Create a Satoshi value from an Integer."
    (Satoshi value))

  (declare satoshi-value (Satoshi -> Integer))
  (define (satoshi-value s)
    "Extract the Integer value from a Satoshi."
    (match s
      ((Satoshi v) v)))

  (declare satoshi-zero (Unit -> Satoshi))
  (define (satoshi-zero)
    "Return zero satoshis."
    (Satoshi 0))

  (declare satoshi-add (Satoshi -> Satoshi -> Satoshi))
  (define (satoshi-add a b)
    "Add two Satoshi values."
    (Satoshi (+ (satoshi-value a) (satoshi-value b))))

  (declare satoshi-sub (Satoshi -> Satoshi -> Satoshi))
  (define (satoshi-sub a b)
    "Subtract Satoshi values."
    (Satoshi (- (satoshi-value a) (satoshi-value b))))

  ;;;; BlockHeight - Block height in the chain
  ;;;;
  ;;;; Genesis block is height 0

  (define-type BlockHeight
    "A block height in the blockchain.
     Genesis block has height 0."
    (BlockHeight U32))

  (declare make-block-height (U32 -> BlockHeight))
  (define (make-block-height height)
    "Create a BlockHeight from a U32."
    (BlockHeight height))

  (declare block-height-value (BlockHeight -> U32))
  (define (block-height-value bh)
    "Extract the U32 value from a BlockHeight."
    (match bh
      ((BlockHeight h) h)))

  (declare block-height-zero (Unit -> BlockHeight))
  (define (block-height-zero)
    "Return block height zero (genesis)."
    (BlockHeight 0))

  (declare block-height-next (BlockHeight -> BlockHeight))
  (define (block-height-next bh)
    "Return the next block height."
    (BlockHeight (+ (block-height-value bh) 1)))

  ;;;; Eq instances for comparing values

  (define-instance (Eq Satoshi)
    (define (== a b)
      (== (satoshi-value a) (satoshi-value b))))

  (define-instance (Eq BlockHeight)
    (define (== a b)
      (== (block-height-value a) (block-height-value b))))

  ;;;; Ord instances for ordering

  (define-instance (Ord Satoshi)
    (define (<=> a b)
      (<=> (satoshi-value a) (satoshi-value b))))

  (define-instance (Ord BlockHeight)
    (define (<=> a b)
      (<=> (block-height-value a) (block-height-value b)))))
