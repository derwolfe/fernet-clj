(ns fernet.frame
  (:import [java.nio ByteBuffer]))

;; sizes of fields in bytes
(def sizes {:version 1
            :timestamp 8
            :iv 16
            :hmac 32})

(def overhead (apply + (vals sizes)))
(def header-size (- (:hmac sizes) overhead))

(defn ^ByteBuffer allocate [ciphertext]
  (ByteBuffer/allocate (+ overhead (alength ciphertext))))

(defn ^ByteBuffer put-header [^ByteBuffer buffer version timestamp iv]
  (doto buffer
    (.put (.byteValue (Short. (short version))))
    (.putLong timestamp)
    (.put iv)))

(defn ^ByteBuffer put [^ByteBuffer buffer value]
  (doto buffer (.put value)))

(defn bytes-to-sign [^ByteBuffer buffer]
  (-> buffer
      (.array)
      (java.util.Arrays/copyOfRange 0 (.position buffer))))

(defn get-bytes [^ByteBuffer buffer size]
  (let [b (byte-array size)]
    (.get buffer b)
    b))

(defn extract-signed [buffer]
  (let [cap (.capacity buffer)
        signed (- cap (:hmac sizes))
        signed-bytes (get-bytes buffer signed)]
    signed-bytes))

(defn decode [b]
  (let [buffer (ByteBuffer/wrap b)
        version (bit-and 0xFF (Short. (short (.get buffer))))
        timestamp (.getLong buffer)
        iv (get-bytes buffer (:iv sizes))
        ciphertext (get-bytes buffer (- (.remaining buffer) (:hmac sizes)))
        hmac (get-bytes buffer (:hmac sizes))
        signed (extract-signed (ByteBuffer/wrap b))]
    {:version version
     :timestamp timestamp
     :iv iv
     :ciphertext ciphertext
     :signed signed
     :hmac hmac}))
