import Init.Data.Nat.Bitwise.Lemmas

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

def originalIndex (r slot : Nat) : Nat :=
  if slot < r then 2 * slot else 2 * (slot - r) + 1

theorem scatter_has_left_inverse (r i : Nat) (valid : i < 2 * r) :
    originalIndex r (destination r i) = i := by
  unfold originalIndex destination
  have parity := Nat.mod_lt i (by decide : 0 < 2)
  by_cases even : i % 2 = 0
  · simp [even]
    split <;> omega
  · have odd : i % 2 = 1 := by omega
    simp [odd]
    split <;> omega

theorem scatter_has_right_inverse (r slot : Nat) :
    destination r (originalIndex r slot) = slot := by
  unfold originalIndex destination
  split
  · have even : (2 * slot) % 2 = 0 := by omega
    simp [even]
  · have odd : (2 * (slot - r) + 1) % 2 = 1 := by omega
    simp [odd]
    omega

theorem integerify_mask (word exponent : Nat) :
    word &&& (2^exponent - 1) = word % 2^exponent := by
  exact Nat.and_two_pow_sub_one_eq_mod word exponent

#print axioms destination_in_range
#print axioms table_slot_in_range
#print axioms scatter_has_left_inverse
#print axioms scatter_has_right_inverse
#print axioms integerify_mask

end Abc.Spec.Scrypt
