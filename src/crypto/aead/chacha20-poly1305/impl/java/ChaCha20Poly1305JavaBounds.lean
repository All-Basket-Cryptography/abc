namespace Abc.Spec.ChaCha20Poly1305.Java

def padding (length : Nat) : Nat := (16 - length % 16) % 16

theorem padding_exact (length : Nat) :
    padding length < 16 ∧ (length + padding length) % 16 = 0 := by
  unfold padding
  omega

theorem transcript_and_fields_fit (aad cipher : Nat) (ha : aad < 2^31) (hc : cipher < 2^31) :
    aad < 2^64 ∧ cipher < 2^64 ∧ (aad + padding aad + cipher + padding cipher + 16) % 16 = 0 := by
  unfold padding
  omega

theorem last_payload_counter (cipher offset : Nat) (fitsArray : cipher < 2^31) (inside : offset < cipher) :
    0 < 1 + offset / 64 ∧ 1 + offset / 64 < 2^32 := by
  omega

#print axioms padding_exact
#print axioms transcript_and_fields_fit
#print axioms last_payload_counter

end Abc.Spec.ChaCha20Poly1305.Java
