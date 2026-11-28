namespace Abc.Spec.X25519

def radix : Nat := 2^51
def modulus : Nat := 2^255 - 19

theorem radix_high_remainder : radix^5 % modulus = 19 := by decide

theorem fold_high_term (low high : Nat) :
    (low + high * radix^5) % modulus = (low + high * 19) % modulus := by
  calc
    _ = (low % modulus + (high * radix^5) % modulus) % modulus := Nat.add_mod _ _ _
    _ = (low % modulus + (high % modulus * 19) % modulus) % modulus := by
      rw [Nat.mul_mod high (radix^5), radix_high_remainder]
    _ = (low % modulus + (high % modulus * (19 % modulus)) % modulus) % modulus := by
      rw [show 19 % modulus = 19 by decide]
    _ = _ := by rw [← Nat.mul_mod, ← Nat.add_mod]

theorem add_nineteen_selects_reduction (x : Nat) (within : x < 2^255) :
    2^255 ≤ x + 19 ↔ modulus ≤ x := by
  unfold modulus
  omega

theorem product_column_fits (a b c d e : Nat) (ha : a < 2^107) (hb : b < 2^107)
    (hc : c < 2^107) (hd : d < 2^107) (he : e < 2^107) :
    a + b + c + d + e < 2^110 := by omega

def inversionExponent : Nat :=
  let power2 := 2
  let power9 := power2 * 2^2 + 1
  let power11 := power9 + power2
  let z5 := power11 * 2 + power9
  let z10 := z5 * 2^5 + z5
  let z20 := z10 * 2^10 + z10
  let z40 := z20 * 2^20 + z20
  let z50 := z40 * 2^10 + z10
  let z100 := z50 * 2^50 + z50
  let z200 := z100 * 2^100 + z100
  let z250 := z200 * 2^50 + z50
  z250 * 2^5 + power11

theorem inversion_chain_exponent : inversionExponent = modulus - 2 := by decide

#print axioms fold_high_term
#print axioms add_nineteen_selects_reduction
#print axioms product_column_fits
#print axioms inversion_chain_exponent

end Abc.Spec.X25519
