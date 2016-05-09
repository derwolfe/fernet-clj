(ns fernet.core
  (:require [fernet.codec.urlbase64 :as urlbase64]
            [fernet.frame :as frame])
  (:import (java.security SecureRandom Security)
           (javax.crypto Cipher Mac)
           (javax.crypto.spec IvParameterSpec SecretKeySpec)
           (org.bouncycastle.jce.provider BouncyCastleProvider)))

(Security/addProvider (new BouncyCastleProvider))

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
    (.nextBytes (new SecureRandom) b)
    b))

(defn split-key [^bytes key-bytes]
  {:signing-key (java.util.Arrays/copyOfRange key-bytes 0 16)
   :crypto-key  (java.util.Arrays/copyOfRange key-bytes 16 32)})

(defn hmac [key to-sign]
  (.doFinal (doto (Mac/getInstance "HMACSHA256")
              (.init (new SecretKeySpec key "HMACSHA256")))
            to-sign))

(defn hmac-verify [key to-sign signature]
  (let [expected-signature (hmac key to-sign)]
    (if (not (org.bouncycastle.util.Arrays/constantTimeAreEqual
                signature
                expected-signature))
      (invalid-token))))

(defn aes128cbc
  [mode key iv message]
  (.doFinal
   (doto (Cipher/getInstance "AES/CBC/PKCS7Padding")
     (.init
      ^int (mode {:encrypt Cipher/ENCRYPT_MODE
                  :decrypt Cipher/DECRYPT_MODE})
      (new SecretKeySpec key "AES")
      (new IvParameterSpec iv)))
   message))

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

(defn decrypt
  "Decrypt the token and return the contents as a byte-array"
  [key token & options]
  (apply decrypt-token key token options))

(defn decrypt-to-string
  "Decrypt the token and return the message as a UTF-8 encoded string"
  [key token & options]
  (String.
   ^bytes (apply decrypt-token key token options)
   (java.nio.charset.Charset/forName "utf-8")))

(defn encrypt
  "Encrypt the message bytes using the provided key and return the ciphertext
  as a string"
  [key message]
  (String. ^String (encrypt-message key message)))

(defn encrypt-string
  "Encrypt the message string using the provided key and return the ciphertext
  as a UTF-8 encoded string"
  [key message]
  (let [utf8-charset (java.nio.charset.Charset/forName "utf-8")
        message-bytes (.getBytes ^String message utf8-charset)]
    (encrypt key message-bytes)))
