namespace Abc.Spec.Argon2id.Jvm

def primaryBlocks (memory lanes : Nat) : Nat := memory - memory % (4 * lanes)

theorem lane_arithmetic_fits_int (lanes : Nat) (valid : lanes < 2 ^ 24) :
    4 * lanes < 2 ^ 31 ∧ 8 * lanes < 2 ^ 31 := by
  omega

theorem provider_count_fits_int (memory lanes : Nat)
    (guard : primaryBlocks memory lanes ≤ 2 ^ 31 - 5) :
    primaryBlocks memory lanes + 4 < 2 ^ 31 := by
  omega

theorem budget_comparison_fits_long (memory lanes tag : Nat)
    (guard : primaryBlocks memory lanes ≤ 2 ^ 31 - 5) (tagBound : tag < 2 ^ 31) :
    1024 * (primaryBlocks memory lanes + 5) + tag < 2 ^ 42 := by
  omega

#print axioms lane_arithmetic_fits_int
#print axioms provider_count_fits_int
#print axioms budget_comparison_fits_long

end Abc.Spec.Argon2id.Jvm
