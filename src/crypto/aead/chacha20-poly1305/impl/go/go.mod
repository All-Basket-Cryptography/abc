module github.com/All-Basket-Cryptography/abc/src/crypto/aead/chacha20-poly1305/impl/go

go 1.24.0

toolchain go1.24.9

require (
	github.com/All-Basket-Cryptography/abc/src/crypto/cipher/chacha20/impl/go v0.0.0
	github.com/All-Basket-Cryptography/abc/src/crypto/mac/poly1305/impl/go v0.0.0
)

replace github.com/All-Basket-Cryptography/abc/src/crypto/cipher/chacha20/impl/go => ../../../../cipher/chacha20/impl/go

replace github.com/All-Basket-Cryptography/abc/src/crypto/mac/poly1305/impl/go => ../../../../mac/poly1305/impl/go
