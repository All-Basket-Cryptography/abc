namespace Abc.Spec.Scrypt.Jvm

def cap : Nat := 2 ^ 31 - 9

theorem bounded_product (stride count : Nat) (positive : 0 < count)
    (guard : stride ≤ cap / count) : stride * count ≤ cap :=
  (Nat.le_div_iff_mul_le positive).mp guard

theorem work_and_output_fit_long (work output : Nat) (hw : work ≤ cap) (ho : output ≤ cap) :
    work + output < 2 ^ 32 := by
  unfold cap at *
  omega

theorem integerify_low_word (lo hi cost : Nat) (divides : (2 ^ 32) % cost = 0) :
    (hi * 2 ^ 32 + lo) % cost = lo % cost := by
  rw [Nat.add_mod, Nat.mul_mod, divides, Nat.mul_zero, Nat.zero_mod, Nat.zero_add, Nat.mod_mod]

def firstBuffer : Nat → Bool
  | 0 => true
  | steps + 1 => !(firstBuffer steps)

theorem romix_returns_to_input (cost : Nat) : firstBuffer (2 * cost) = true := by
  induction cost with
  | zero => rfl
  | succ n ih =>
    rw [show 2 * (n + 1) = (2 * n + 1) + 1 by omega]
    simp [firstBuffer, ih]

#print axioms bounded_product
#print axioms work_and_output_fit_long
#print axioms integerify_low_word
#print axioms romix_returns_to_input

end Abc.Spec.Scrypt.Jvm
