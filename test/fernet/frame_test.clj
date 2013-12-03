(ns fernet.frame-test
  (:require [clojure.test :refer :all]
            [fernet.core :refer :all]
            [fernet.codec :refer :all]
            [fernet.frame :as frame]))

(def an-frame
  (str "80000000000000000a10101010101010101010101010101010666f6f626172"
       "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"))

(deftest decode-test
  (let [decoded (frame/decode-token (unhex an-frame))]
    (is (= [:ciphertext :hmac :iv :signed :timestamp :version]
           (sort (keys decoded))))
    (is (= 0x80 (:version decoded)))
    (is (= 10 (:timestamp decoded)))
    (is (= (hex (byte-array (map byte (repeat 16 16))))
           (hex (:iv decoded))))
    (is (= "666f6f626172" (hex (:ciphertext decoded))))
    (is (= "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
           (hex (:hmac decoded))))
    (is (= "80000000000000000a10101010101010101010101010101010666f6f626172"
           (hex (:signed decoded))))))
