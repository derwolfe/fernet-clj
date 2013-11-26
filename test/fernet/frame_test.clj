(ns fernet.frame-test
  (:require [clojure.test :refer :all]
            [fernet.core :refer :all]
            [fernet.codec :refer :all]
            [fernet.frame :as frame]))

(defn as-bytes [s]
  (byte-array (map byte s)))

(deftest bytes-to-sign-test
  (testing "bytes to sign returns byte-array of versiontimestampivciphertext"
    (is (= "80000000000000000a10101010101010101010101010101010666f6f626172"
           (let [version 0x80
                 timestamp 10
                 iv (as-bytes (repeat 16 16))
                 ciphertext (as-bytes "foobar")
                 b (doto (frame/allocate ciphertext)
                     (frame/put-header version timestamp iv)
                     (frame/put ciphertext))]
             (hex (frame/bytes-to-sign b)))))))

(def an-frame
  (str "80000000000000000a10101010101010101010101010101010666f6f626172"
       "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"))

(deftest decode-test
  (testing "frame decoding"
    (let [decoded (frame/decode-token (unhex an-frame))]
      (is (= [:ciphertext :hmac :iv :signed :timestamp :version]
             (sort (keys decoded))))
      (is (= 0x80 (:version decoded)))
      (is (= 10 (:timestamp decoded)))
      (is (= (hex (as-bytes (repeat 16 16)))
             (hex (:iv decoded))))
      (is (= "666f6f626172" (hex (:ciphertext decoded))))
      (is (= "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
             (hex (:hmac decoded))))
      (is (= "80000000000000000a10101010101010101010101010101010666f6f626172"
             (hex (:signed decoded)))))))
