import Init.Data.Nat.Bitwise.Lemmas

namespace Abc.Spec.MlKem768.Jvm

theorem nibble_mask (b : Nat) : b &&& 15 = b % 16 := by
  exact Nat.and_two_pow_sub_one_eq_mod b 4

theorem coefficient_word_fits (a b c : Nat) (ha : a < 256) (hb : b < 256) (hc : c < 256) :
    a + 256 * (b % 16) < 4096 ∧ b / 16 + 16 * c < 4096 := by omega

theorem canonical_check_excludes_modulus (x : Nat) (accepted : x < 3329) :
    x % 3329 = x ∧ x ≠ 3329 := by omega

theorem coefficient_triple_in_public_key (i : Nat) (inTriples : i < 384) :
    3 * i + 2 < 1152 ∧ 3 * i + 2 < 1184 := by omega

#print axioms nibble_mask
#print axioms coefficient_word_fits
#print axioms canonical_check_excludes_modulus
#print axioms coefficient_triple_in_public_key

end Abc.Spec.MlKem768.Jvm
