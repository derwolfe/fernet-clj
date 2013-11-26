(ns fernet
  (:require [fernet.core :as core]))

(defn generate-key []
  (core/b64encode (core/secure-random 32)))

(defn encrypt [key message]
  (String. (core/encrypt key message)))

(defn decrypt [key token & options]
  (apply core/decrypt key token options))
