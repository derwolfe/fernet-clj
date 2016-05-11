(ns fernet.frame
  (:require [clojurewerkz.buffy.core :as bc]
            [clojurewerkz.buffy.types.protocols :as bp]))

;; extend buffy
(deftype UByteType []
  bp/BuffyType
  (size [_] 1)
  (write [bt buffer idx value]
    (.setByte buffer idx value))
  (read [by buffer idx]
    (bit-and 0xFF (.getByte buffer idx))))

(def ubyte-type (memoize #(UByteType.)))

(def token-spec {:version (ubyte-type)
                 :timestamp (bc/long-type)
                 :iv (bc/bytes-type 16)
                 :ciphertext nil
                 :hmac (bc/bytes-type 32)})

(def overhead
  (apply + (map #(bp/size (second %)) (dissoc token-spec :ciphertext))))

(defn token-buf [ciphertext-length]
  (let [spec (assoc token-spec :ciphertext (bc/bytes-type ciphertext-length))]
    (bc/compose-buffer spec :buffer-type :heap)))

(defn fill-buffer [buf b]
  (.setBytes (bc/buffer buf) 0 b)
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
    (bc/compose buf {:version version
                     :timestamp timestamp
                     :iv iv
                     :ciphertext ciphertext})
    (bc/set-field buf :hmac (hmac-fn (get-bytes (bc/buffer buf) signed-length)))
    (.array (bc/buffer buf))))

(defn decode-token
  [b]
  (let [signed-length (- (alength b) 32)
        buf (token-buf (- (alength b) overhead))]
    (fill-buffer buf b)
    (assoc (bc/decompose buf) :signed (get-bytes (bc/buffer buf) signed-length))))
