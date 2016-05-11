(defproject fernet "0.4.0-SNAPSHOT"
  :description "Authenticated symmetric encryption made easy."
  :url "https://github.com/derwolfe/fernet-clj"
  :license {:name "MIT"
            :url "https://raw.github.com/derwolfe/fernet-clj/master/LICENSE"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.bouncycastle/bcprov-jdk15on "1.54"]
                 [commons-codec/commons-codec "1.10"]
                 [clojurewerkz/buffy "1.0.2"]]
  :profiles {:dev {:resource-paths ["test/resources"]
                   :dependencies [[org.clojure/data.json "0.2.6"]
                                  [clj-time "0.11.0"]
                                  [perforate "0.3.4"]]
                   :plugins [[perforate "0.3.3"]
                             [lein-autodoc "0.9.0"]
                             [lein-ancient "0.6.8"]]}}
  :deploy-repositories [["releases" :clojars]
                        ["snapshots" :clojars]]
  :global-vars {*warn-on-reflection* true})
