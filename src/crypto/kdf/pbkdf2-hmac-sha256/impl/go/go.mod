module github.com/All-Basket-Cryptography/abc/src/crypto/kdf/pbkdf2-hmac-sha256/impl/go

go 1.24.0

toolchain go1.24.9

require github.com/All-Basket-Cryptography/abc/src/crypto/mac/hmac-sha256/impl/go v0.0.0

require github.com/All-Basket-Cryptography/abc/src/crypto/hash/sha256/impl/go v0.0.0 // indirect

replace github.com/All-Basket-Cryptography/abc/src/crypto/mac/hmac-sha256/impl/go => ../../../../mac/hmac-sha256/impl/go

replace github.com/All-Basket-Cryptography/abc/src/crypto/hash/sha256/impl/go => ../../../../hash/sha256/impl/go
