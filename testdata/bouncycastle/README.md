# Bouncy Castle interoperability fixtures

Generated once by `interop/bouncycastle/generate.sh` with Bouncy Castle 1.80. The `*.key` files
are the **private keys of throwaway test identities** (`O=cryptomsg interop`), committed so the
Go tests can decrypt and verify without a JVM. They secure nothing: never trust these
certificates or use these keys outside this test suite.
