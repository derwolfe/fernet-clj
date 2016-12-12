(ns fernet.core
  (:require [fernet.codec.urlbase64 :as urlbase64]
            [fernet.frame :as frame]
            [clojure.spec :as s]
            [clojure.test.check.generators :as gen])
  (:import (java.security SecureRandom Security)
           (javax.crypto Cipher Mac)
           (javax.crypto.spec IvParameterSpec SecretKeySpec)
           (org.bouncycastle.jce.provider BouncyCastleProvider)))

(Security/addProvider (BouncyCastleProvider.))

(def version 0x80)

(defn- invalid-token
  "Throw an invalid token error."
  []
  (throw (ex-info "Invalid token." {})))

(defn- now []
  "The current time in seconds since the epoch 1970-01-01T00:00:00Z."
  (int (/ (System/currentTimeMillis) 1000)))

(defn- secure-random [size]
  "Generate secure random byte-array of 'size'."
  (let [b (byte-array size)]
    (.nextBytes (SecureRandom.) b)
    b))

(defn split-key [^bytes key-bytes]
  {:signing-key (java.util.Arrays/copyOfRange key-bytes 0 16)
   :crypto-key  (java.util.Arrays/copyOfRange key-bytes 16 32)})

(defn hmac [key to-sign]
  (.doFinal (doto (Mac/getInstance "HMACSHA256")
              (.init (SecretKeySpec. key "HMACSHA256")))
            to-sign))

(defn hmac-verify [key to-sign signature]
  (let [expected-signature (hmac key to-sign)]
    (if (not (org.bouncycastle.util.Arrays/constantTimeAreEqual
                signature
                expected-signature))
      (invalid-token))))

(defn- aes128cbc
  [mode key iv message]
  (let [cipher (Cipher/getInstance "AES/CBC/PKCS7Padding")
        mode (mode {:encrypt Cipher/ENCRYPT_MODE
                    :decrypt Cipher/DECRYPT_MODE})
        k (SecretKeySpec. key "AES")
        iv (IvParameterSpec. iv)]
    (.doFinal
     (doto cipher
       (.init ^int mode k iv))
     message)))

(defn generate-key [] (urlbase64/encode (secure-random 32)))

(defn encrypt-message [key-material message
                       & {:keys [iv timestamp]
                          :or {iv (secure-random 16) timestamp (now)}}]
  (let [{:keys [signing-key crypto-key]}
        (split-key (urlbase64/decode key-material))
        ciphertext (aes128cbc :encrypt crypto-key iv message)]
    (urlbase64/encode
      (frame/encode-token {:version version
                           :timestamp timestamp
                           :iv iv
                           :ciphertext ciphertext
                           :hmac-fn #(hmac signing-key %)}))))

(defn- check-ttl [ttl now ts max-clock-skew]
  (if (not (nil? ttl))
    (if (or
          (> now (+ ts ttl))
          (> ts (+ now max-clock-skew)))
      (invalid-token))))

(defn decrypt-token [key-material token
                     & {:keys [ttl now max-clock-skew]
                        :or {ttl nil now (now) max-clock-skew 60}}]
  (try
    (let [{:keys [signing-key crypto-key]}
            (split-key (urlbase64/decode key-material))
          decoded (frame/decode-token (urlbase64/decode token))]
      (check-ttl ttl now (:timestamp decoded) max-clock-skew)
      (hmac-verify signing-key (:signed decoded) (:hmac decoded))
      (aes128cbc :decrypt crypto-key (:iv decoded) (:ciphertext decoded)))
    (catch Exception e
      (invalid-token))))

;; (s/def :token bytes)

;; come up with a spec that describes decrypt


(defn decrypt
  "Decrypt the token using the key

  key - a base64 encoded string
  token - a byte-array

  returns the message as a byte-array"
  [key token & options]
  (apply decrypt-token key token options))

(defn decrypt-to-string
  "Decrypt the token using the key

  key - a base64 encoded string
  token - a byte-array

  returns the message as a UTF-8 encoded string"
  [key token & options]
  (String.
   ^bytes (apply decrypt-token key token options)
   (java.nio.charset.Charset/forName "utf-8")))

;; a key is a base64 url encoded string that is 32 bytes (256 bits)
;; this could just use a regex like
;; RFC below defines possible characters in base64 urlsafe
;; https://tools.ietf.org/html/rfc4648#page-7
;; (def b64urlsafe-regex #"^(?:[A-Za-z0-9_-+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?32$")
;; but how should it be encoded that this needs to be securely random?

;; how to encode that a key needs to be securely randomized 32 bytes. These need
;; to be encoded as urlsafe base64
(s/def ::key (s/and string? :min-count 32 :max-count 32))
(s/def ::message bytes?)
(s/def ::token bytes?)

(s/fdef encrypt
        :args (s/cat :key ::key :message ::message)
        :ret ::token)

(def email-regex #"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$")
(s/def ::email-type (s/and string? #(re-matches email-regex %)))
(def kw-gen-3 (gen/fmap #(keyword "my.domain" %)
                        (gen/such-that #(not= % "")
                                       (gen/string-alphanumeric))))

#_ (s/exercise (:args (s/get-spec `encrypt)))
#_ (gen/sample (s/gen ::email-type))


(defn encrypt
  "Encrypt the message using the key

  key - a base64 encoded string
  message - a byte-array

  returns the ciphertext as a urlsafe base64 encoded string"
  [key message]
  (encrypt-message key message))

(defn encrypt-string
  "Encrypt the message using the key

  key - a base64 encoded string
  message-string - a UTF-8 encoded string

  returns the ciphertext as a urlsafe base64 encoded string"
  [key message-string]
  (let [utf8-charset (java.nio.charset.Charset/forName "utf-8")
        message-bytes (.getBytes ^String message-string utf8-charset)]
    (encrypt key message-bytes)))
