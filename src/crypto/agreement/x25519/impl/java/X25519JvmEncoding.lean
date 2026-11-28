namespace Abc.Spec.X25519.Jvm

def topBit : Nat := 2 ^ 255
def field : Nat := topBit - 19
def normalize (word : Nat) : Nat := (word % topBit) % field

theorem normalized_coord_in_field (word : Nat) : normalize word < field := by
  exact Nat.mod_lt _ (by decide)

theorem high_bit_ignored (word : Nat) : normalize (word + topBit) = normalize word := by
  unfold normalize
  rw [Nat.add_mod, Nat.mod_self, Nat.add_zero, Nat.mod_mod]

theorem canonical_kept (word : Nat) (range : word < field) : normalize word = word := by
  simp only [normalize, field, topBit] at *
  omega

theorem aliases_reduce (offset : Nat) (range : offset < 19) : normalize (field + offset) = offset := by
  simp only [normalize, field, topBit] at *
  omega

#print axioms normalized_coord_in_field
#print axioms high_bit_ignored
#print axioms canonical_kept
#print axioms aliases_reduce

end Abc.Spec.X25519.Jvm
