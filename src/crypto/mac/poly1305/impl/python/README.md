# Poly1305 in Python

`authenticate` takes a 32-byte one-time key and returns a 16-byte tag.
`Mac.update` and `Mac.finish` support incremental input. The streaming
state owns a copy of its partial block and rejects updates after
finalization. Repeated finalization returns the same immutable tag.
Use a fresh one-time key for every distinct message.
[RFC 8439 §2.5 and Appendix A.3](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5) · [Poly1305 design paper](https://doi.org/10.1007/11502760_3)

The implementation follows the polynomial recurrence with Python
integers. The tests check eight RFC vectors at every split point,
512 independent expanded-polynomial comparisons and 96 OpenSSL
ChaCha20-Poly1305 tags. Setting `ABC_OPENSSL` to an OpenSSL executable
also enables 32 direct Poly1305 comparisons. The repository has a Lean
model for the modular recurrence. Full Python source refinement,
interpreter timing, and runtime key erasure require further evidence.
[Lean modular recurrence model](../go/Poly1305GoModel.lean)

```sh
python -B -m unittest discover -s src/crypto/mac/poly1305/impl/python -p test_poly1305.py -v
```

The independent AEAD provider comparison uses Node on the path.
