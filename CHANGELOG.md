0.3.0

- Add `lein ancient` to automatically check for out of date dependencies in CI
- Update dependencies to satisfy `lein ancient`
- replace calls to `clojurewerkz.buffy.core/set-fields` with
  `clojurewerkz.buffy.core.compose`. This was due to a name change in Buffy.
- remove the use of `:refer :all` in `fernet.frame` and replace with explicit
  namespace aliases for `clojurewerkz.buffy.core` and
  `clojurewerkz.buffy.types.protocols`

0.2.0

- Add `fernet.core/encrypt-string` and `fernet.core/decrypt-to-string` functions
- Remove `fernet.core/aes128cbc` from public API.
