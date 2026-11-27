namespace Abc.Spec.ChaCha20Poly1305

def padding (len : Nat) : Nat := (16 - len % 16) % 16
def macLength (aad cipher : Nat) : Nat := aad + padding aad + cipher + padding cipher + 16

theorem padding_length_bound (len : Nat) : padding len < 16 := by
  exact Nat.mod_lt _ (by decide)

theorem aligned_mac_input (aad cipher : Nat) : macLength aad cipher % 16 = 0 := by
  unfold macLength padding
  omega

theorem payload_excludes_poly_key_counter (length index : Nat)
    (admitted : length ≤ (2^32 - 1) * 64)
    (inBlocks : index < (length + 63) / 64) :
    0 < 1 + index ∧ 1 + index < 2^32 := by
  omega

#print axioms aligned_mac_input
#print axioms payload_excludes_poly_key_counter

end Abc.Spec.ChaCha20Poly1305
