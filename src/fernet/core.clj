(ns fernet.core
  (:require [fernet.frame :as frame])
  (:import [org.bouncycastle.jce.provider BouncyCastleProvider]
           [java.security SecureRandom Security]
           [java.nio ByteBuffer]
           [javax.crypto Cipher Mac]
           [javax.crypto.spec SecretKeySpec IvParameterSpec]
           [org.apache.commons.codec.binary Base64 Hex]))

(Security/addProvider (new BouncyCastleProvider))

(def version 0x80)

(defn invalid-token []
  (throw (ex-info "Invalid token." {})))

(defn hexlify [b]
  (Hex/encodeHexString b))

(defn unhexlify [s]
  (Hex/decodeHex (char-array s)))

(defn b64encode [b]
  (Base64/encodeBase64URLSafeString b))

(defn b64decode [s]
  (Base64/decodeBase64 s))

(defn now []
  (int (/ (System/currentTimeMillis) 1000)))

(defn secure-random [size]
  (let [b (byte-array size)]
    (.nextBytes (new SecureRandom) b)
    b))

(defn split-key [key-bytes]
  {:signing-key (java.util.Arrays/copyOfRange key-bytes 0 16)
   :crypto-key  (java.util.Arrays/copyOfRange key-bytes 16 32)})

(defn hmac [signing-key to-sign]
  (.doFinal (doto (Mac/getInstance "HMACSHA256")
              (.init (new SecretKeySpec signing-key "HMACSHA256")))
            to-sign))

(defn hmac-verify [signing-key to-sign signature]
  (let [expected-signature (hmac signing-key to-sign)]
    (if (not (org.bouncycastle.util.Arrays/constantTimeAreEqual
                signature
                expected-signature))
      (invalid-token))))

(defn aes [mode encrypt-key iv message]
  (.doFinal (doto (Cipher/getInstance "AES/CBC/PKCS7Padding")
              (.init
                (mode {:encrypt Cipher/ENCRYPT_MODE
                       :decrypt Cipher/DECRYPT_MODE})
                (new SecretKeySpec encrypt-key "AES")
                (new IvParameterSpec iv)))
            message))

(defn encrypt [key-material message
               & {:keys [iv timestamp]
                  :or {iv (secure-random 16) timestamp (now)}}]
  (let [{:keys [signing-key crypto-key]} (split-key (b64decode key-material))
        ciphertext (aes :encrypt crypto-key iv message)
        token (frame/allocate ciphertext)]
    (-> token
        (frame/put-header version timestamp iv)
        (frame/put ciphertext)
        (frame/put (hmac signing-key (frame/bytes-to-sign token)))
        (.array)
        (b64encode))))

(defn check-ttl [ttl now ts max-clock-skew]
  (if (not (nil? ttl))
    (if (or
          (> now (+ ts ttl))
          (> ts (+ now max-clock-skew)))
      (invalid-token))))

(defn decrypt [key-material token
               & {:keys [ttl now max-clock-skew]
                  :or {ttl nil now (now) max-clock-skew 60}}]
  (try
    (let [{:keys [signing-key crypto-key]} (split-key (b64decode key-material))
          decoded (frame/decode (b64decode token))]
      (check-ttl ttl now (:timestamp decoded) max-clock-skew)
      (hmac-verify signing-key (:signed decoded) (:hmac decoded))
      (aes :decrypt crypto-key (:iv decoded) (:ciphertext decoded)))
    (catch Exception e (invalid-token))))
