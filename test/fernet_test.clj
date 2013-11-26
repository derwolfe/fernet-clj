(ns fernet-test
  (:use [fernet.core :only [hexlify unhexlify]])
  (:require [clojure.test :refer :all]
            [fernet :refer :all]))

(def k (generate-key))

(deftest api-tests
  (testing "encrypt/decrypt round trip"
    (is (java.util.Arrays/equals
          (byte-array (map byte "hello world"))
          (decrypt k (encrypt k (byte-array (map byte "hello world"))))))))
