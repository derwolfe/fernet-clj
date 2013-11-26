(ns fernet.codec
  (:import [org.apache.commons.codec.binary Hex]))

(defn hex
  "Return a hex encoded string of the value of 'b'"
  [b]
  (Hex/encodeHexString b))

(defn unhex
  "Return a byte-array of the value of the hex encoded string 'h'"
  [h]
  (Hex/decodeHex (char-array h)))
