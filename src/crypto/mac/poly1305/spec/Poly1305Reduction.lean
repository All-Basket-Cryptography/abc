namespace Abc.Spec.Poly1305

def radix : Nat := 2^26
def modulus : Nat := 2^130 - 5

theorem radix_high_remainder : radix^5 % modulus = 5 := by decide

theorem fold_high_term (low high : Nat) :
    (low + high * radix^5) % modulus = (low + high * 5) % modulus := by
  calc
    _ = (low % modulus + (high * radix^5) % modulus) % modulus := Nat.add_mod _ _ _
    _ = (low % modulus + (high % modulus * 5) % modulus) % modulus := by
      rw [Nat.mul_mod high (radix^5), radix_high_remainder]
    _ = (low % modulus + (high % modulus * (5 % modulus)) % modulus) % modulus := by
      rw [show 5 % modulus = 5 by decide]
    _ = _ := by rw [← Nat.mul_mod, ← Nat.add_mod]

theorem add_five_selects_reduction (x : Nat) (within : x < 2^130) :
    2^130 ≤ x + 5 ↔ modulus ≤ x := by
  unfold modulus
  omega

theorem five_products_fit (a b c d e : Nat) (ha : a < 2^57) (hb : b < 2^57)
    (hc : c < 2^57) (hd : d < 2^57) (he : e < 2^57) :
    a + b + c + d + e < 2^64 := by omega

#print axioms fold_high_term
#print axioms add_five_selects_reduction
#print axioms five_products_fit

end Abc.Spec.Poly1305
