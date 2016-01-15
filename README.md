# fernet

[![Build Status](https://travis-ci.org/dreid/fernet-clj.png?branch=master)](https://travis-ci.org/dreid/fernet-clj)

A Clojure implementation of [fernet](https://github.com/fernet/spec).

Fernet's goal is to provide simple and sane authenticated symmetric encryption.

fernet-clj currently supports version ``0x80`` of the fernet specification.

## Usage

First, if you use leiningen, add the following to your dependencies:

[![Latest Version](https://clojars.org/fernet/latest-version.svg)](https://clojars.org/fernet)

To encrypt some data we must generate a key:

```clojure
user=> (require 'fernet.core)
nil
user=> (def k (fernet.core/generate-key))
#'user/k
user=> k
"n7i7vTDV5pXGYRyyYznsUDydOi8KJLTiIX1kUTSfxr0"
```

Fernet keys are defined as a 128-bit signing key and a 128-bit encryption key
that have been URL-safe base64 encoded. ``fernet.core/generate-key`` returns a
randomly generated key of this form as a string.

Once you have a key you can encrypt some messages:

```clojure
user=> (def m (byte-array (map byte "Hello, world!")))
#'user/m
user=> m
#<byte[] [B@5502abdb>
(def token (fernet.core/encrypt k m))
user=> (def token (fernet.core/encrypt k m))
#'user/token
user=> token
"gAAAAABSlDV-AteaTbF7zoG4IFmRxAdyXrgONgSbsQ_FHTnvv2tJCAs4WSJPXa5Ai3OnUSqjSmjX5VH8Ka5G9EOXLaRw3Er5Qg"
```

``fernet.core/encrypt`` returns a Fernet `token` which is a URL-safe base64
encoded series of bytes according to the spec and depending on version.
Generally it includes a verions identifier, followed by an iv, a timestamp,
the ciphertext, and an HMAC over the preceding fields.

They can of course be decrypted with the same key:

```clojure
user=> (def out-m (fernet.core/decrypt k token))
#'user/out-m
user=> out-m
#<byte[] [B@22adc446>
user=> (String. out-m)
"Hello, world!"
```

The timestamp contained in the Fernet `token` is the time at which the token
was generated.  ``fernet.core/decrypt`` takes a ``:ttl`` argument which will
cause it to reject any token that is older than the specified number of
seconds.

```clojure
user=> (Thread/sleep 5000)
nil
user=> (fernet.core/decrypt k token :ttl 5)

ExceptionInfo Invalid token.  clojure.core/ex-info (core.clj:4327)
```

## Todo

* encrypt/decrypt edn terms
* autodoc?

## License

Copyright © 2013 David Reid

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

