(defproject fernet "0.1.1-SNAPSHOT"
  :description "Authenticated symmetric encryption made easy."
  :url "https://github.com/dreid/fernet-clj"
  :license {:name "MIT"
            :url "https://raw.github.com/dreid/fernet-clj/master/LICENSE"}
  :dependencies [[org.clojure/clojure "1.5.1"]
                 [org.bouncycastle/bcprov-jdk15on "1.49"]
                 [commons-codec/commons-codec "1.8"]
                 [clojurewerkz/buffy "0.3.0"]]
  :profiles {:dev {:resource-paths ["test/resources"]
                   :dependencies [[org.clojure/data.json "0.2.3"]
                                  [clj-time "0.6.0"]
                                  [perforate "0.3.3"]]
                   :plugins [[perforate "0.3.3"]
                             [lein-autodoc "0.9.0"]]}}
  :deploy-repositories [["releases" :clojars]
                        ["snapshots" :clojars]]
  :global-vars {*warn-on-reflection* true})
