(ns fernet.core-test
  (:use [clj-time.format :only [parse]]
        [clj-time.coerce :only [to-long]])
  (:require [clojure.data.json :as json]
            [clojure.test :refer :all]
            [clojure.java.io :as io]
            [fernet.core :refer :all])
  (:import [org.apache.commons.codec.binary Base64 Hex]
           [java.util Arrays]))

(defn as-bytes [s]
  (byte-array (map byte s)))

(defn parse-now [now-str]
  (/ (to-long (parse now-str)) 1000))

(defn json-resource [resource]
  (json/read-str (slurp (io/resource resource)) :key-fn keyword))

(deftest aes-encryption
  (testing
    (is (= "7649abac8119b246cee98e9b12e9197d8964e0b149c10b7b682e6e39aaeb731c"
           (hexlify
              (aes :encrypt (unhexlify "2b7e151628aed2a6abf7158809cf4f3c")
                            (unhexlify "000102030405060708090A0B0C0D0E0F")
                            (unhexlify "6bc1bee22e409f96e93d7e117393172a")))))))

(deftest hmac-signing
  (testing
    (is (= "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
           (hexlify
             (hmac (unhexlify "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
                   (unhexlify "4869205468657265")))))))

(defn key= [a b]
  (apply = (cons true (map (fn [k] (Arrays/equals (k a) (k b))) (keys a)))))

(deftest split-key-tests
  (testing
    (let [signing-seq (map byte (repeat 16 1))
          crypto-seq (map byte (repeat 16 2))
          signing-bytes (byte-array signing-seq)
          crypto-bytes (byte-array crypto-seq)
          key-material (byte-array (concat signing-seq crypto-seq))
          split-material (split-key key-material)]
      (is (Arrays/equals signing-bytes (:signing-key split-material)))
      (is (Arrays/equals crypto-bytes (:crypto-key split-material))))))

(defn unpad [b64]
  (apply str (take-while #(not (= \= %)) b64)))

(deftest generation
  (doseq [fixture (json-resource "generate.json")
          :let [{:keys [token secret iv now src]} fixture]]
    (testing
      (is (= (unpad token)
             (encrypt secret
                      (as-bytes src)
                      :iv (as-bytes iv)
                      :timestamp (parse-now now)))))))

(deftest verification
  (doseq [fixture (json-resource "verify.json")
          :let [{:keys [token secret ttl_sec now src]} fixture]]
    (testing
      (is (= src
             (String. (decrypt secret
                               token
                               :ttl ttl_sec
                               :now (parse-now now))))))))

(deftest invalid-tokens
  (doseq [fixture (json-resource "invalid.json")
          :let [{:keys [desc token secret now ttl_sec]} fixture]]
    (testing (str "invalid token: " desc)
      (is (thrown? clojure.lang.ExceptionInfo
                   (decrypt secret
                            token
                            :ttl ttl_sec
                            :now (parse-now now)))))))
