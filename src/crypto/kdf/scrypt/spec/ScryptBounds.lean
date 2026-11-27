namespace Abc.Spec.Scrypt

def destination (r i : Nat) : Nat := i / 2 + (i % 2) * r

theorem destination_in_range (r i : Nat) (valid : i < 2 * r) :
    destination r i < 2 * r := by
  have parity := Nat.mod_lt i (by decide : 0 < 2)
  by_cases even : i % 2 = 0
  · simp [destination, even]
    omega
  · have odd : i % 2 = 1 := by omega
    simp [destination, odd]
    omega

theorem table_slot_in_range (count slot stride : Nat) (valid : slot < count) :
    (slot + 1) * stride ≤ count * stride :=
  Nat.mul_le_mul_right stride (by omega)

#print axioms destination_in_range
#print axioms table_slot_in_range

end Abc.Spec.Scrypt
