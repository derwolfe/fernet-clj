(ns fernet.codec.urlbase64
  (:import (org.apache.commons.codec.binary Base64)))

(defn encode
  "URL-Safe Base64 encode 'b' and return a 'String'."
  [b]
  (Base64/encodeBase64URLSafeString b))

(defn decode
  "Decode a URL-Safe Base64 string 's' and return a byte-array."
  [s]
  (Base64/decodeBase64 s))
