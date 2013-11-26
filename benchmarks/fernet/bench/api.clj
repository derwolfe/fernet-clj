(ns fernet.bench.api
  (:use perforate.core
        fernet))

(defgoal encryption "fernet encryption")


(def k "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=")

(def m "hello")
(def mb (byte-array (map byte m)))

(defcase encryption :basic
  []
  (encrypt k mb))

(defgoal decryption "fernet decryption")

(def token (str "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_"
                "5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA=="))

(defcase decryption :basic
  []
  (decrypt k token))
