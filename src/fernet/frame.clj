(ns fernet.frame
  (:require [clojurewerkz.buffy.core :refer :all]
            [clojurewerkz.buffy.util :refer [hex-dump]]
            [clojurewerkz.buffy.types.protocols :refer :all]
            [fernet.codec :refer [hex]])
  (:import [java.nio ByteBuffer]))

;; extend buffy
(deftype UByteType []
  BuffyType
  (size [_] 1)
  (write [bt buffer idx value]
    (.setByte buffer idx value))
  (read [by buffer idx]
    (bit-and 0xFF (.getByte buffer idx))))

(def ubyte-type (memoize #(UByteType.)))

(def token-spec {:version (ubyte-type)
                 :timestamp (long-type)
                 :iv (bytes-type 16)
                 :ciphertext nil
                 :hmac (bytes-type 32)})

(def overhead
  (apply + (map #(size (second %)) (dissoc token-spec :ciphertext))))

(defn token-buf [ciphertext-length]
  (let [spec (assoc token-spec :ciphertext (bytes-type ciphertext-length))]
    (compose-buffer spec :buffer-type :heap)))

(defn fill-buffer [buf b]
  (.setBytes (buffer buf) 0 b)
  buf)

(defn get-bytes
  ([buf length]
    (get-bytes buf 0 length))
  ([buf start length]
   (let [b (byte-array length)]
     (.getBytes buf start b 0 length)
     b)))

(defn encode-token
  [{:keys [version ciphertext iv timestamp hmac-fn]}]
  (let [ciphertext-length (alength ciphertext)
        signed-length (- (+ overhead ciphertext-length) 32)
        buf (token-buf ciphertext-length)]
    (set-fields buf {:version version
                     :timestamp timestamp
                     :iv iv
                     :ciphertext ciphertext})
    (set-field buf :hmac (hmac-fn (get-bytes (buffer buf) signed-length)))
    (.array (buffer buf))))

(defn decode-token
  [b]
  (let [signed-length (- (alength b) 32)
        buf (token-buf (- (alength b) overhead))]
    (fill-buffer buf b)
    (assoc (decompose buf) :signed (get-bytes (buffer buf) signed-length))))
