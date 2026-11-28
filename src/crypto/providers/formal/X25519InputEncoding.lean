import Init.Data.Nat.Bitwise.Lemmas

namespace Abc.Spec.ProviderInputs.X25519

def topBit : Nat := 2 ^ 255
def modulus : Nat := topBit - 19
def rawLimit : Nat := 2 * topBit

def mask (wire : Nat) : Nat := wire &&& (topBit - 1)
def normalize (wire : Nat) : Nat := mask wire % modulus

theorem mask_is_low_255_bits (wire : Nat) : mask wire = wire % topBit := by
  exact Nat.and_two_pow_sub_one_eq_mod wire 255

theorem mask_bound (wire : Nat) : mask wire < topBit := by
  rw [mask_is_low_255_bits]
  exact Nat.mod_lt _ (by decide)

theorem normalization_range (wire : Nat) : normalize wire < modulus := by
  exact Nat.mod_lt _ (by decide)

theorem high_bit_does_not_change_normalization (wire : Nat) :
    normalize (wire + topBit) = normalize wire := by
  unfold normalize
  rw [mask_is_low_255_bits, mask_is_low_255_bits, Nat.add_mod, Nat.mod_self, Nat.add_zero, Nat.mod_mod]

theorem normalize_is_single_subtraction (wire : Nat) :
    normalize wire = if modulus ≤ mask wire then mask wire - modulus else mask wire := by
  have bound := mask_bound wire
  unfold normalize
  simp only [modulus, topBit] at *
  split <;> omega

theorem canonical_encoding_unchanged (wire : Nat) (canonical : wire < modulus) :
    normalize wire = wire := by
  rw [normalize, mask_is_low_255_bits]
  simp only [modulus, topBit] at *
  omega

theorem normalize_idempotent (wire : Nat) : normalize (normalize wire) = normalize wire :=
  canonical_encoding_unchanged _ (normalization_range wire)

theorem mask_when_wire_has_256_bits (wire : Nat) (bound : wire < rawLimit) :
    mask wire = if wire < topBit then wire else wire - topBit := by
  rw [mask_is_low_255_bits]
  simp only [rawLimit, topBit] at *
  split <;> omega

theorem mask_matches_final_byte (low octet : Nat) (lowWidth : low < 2 ^ 248) :
    mask (low + (octet <<< 248)) = low + ((octet &&& 127) <<< 248) := by
  rw [mask_is_low_255_bits]
  have byteMask : octet &&& 127 = octet % 2 ^ 7 :=
    Nat.and_two_pow_sub_one_eq_mod octet 7
  simp only [byteMask, Nat.shiftLeft_eq, topBit]
  omega

-- Field values below 19 have four representatives in the wire domain, two
-- of which use a noncanonical masked integer. The rest have two.
theorem all_wire_aliases (wire value : Nat) (wireBound : wire < rawLimit)
    (canonical : value < modulus) :
    normalize wire = value ↔
      (wire = value ∨ wire = value + topBit) ∨
        (value < 19 ∧ (wire = value + modulus ∨ wire = value + modulus + topBit)) := by
  rw [normalize_is_single_subtraction, mask_when_wire_has_256_bits wire wireBound]
  simp only [modulus, rawLimit, topBit] at *
  split <;> split <;> omega

theorem extra_aliases_fit_iff (value : Nat) :
    value + modulus < topBit ↔ value < 19 := by
  simp only [modulus, topBit]
  omega

theorem aliases_distinct (value : Nat) :
    value < value + modulus ∧ value + modulus < value + topBit ∧
      value + topBit < value + modulus + topBit := by
  simp only [modulus, topBit]
  omega

theorem raw_limit_is_256_bits : rawLimit = 2 ^ 256 := by decide

#print axioms mask_is_low_255_bits
#print axioms mask_bound
#print axioms normalization_range
#print axioms high_bit_does_not_change_normalization
#print axioms normalize_is_single_subtraction
#print axioms canonical_encoding_unchanged
#print axioms normalize_idempotent
#print axioms mask_when_wire_has_256_bits
#print axioms mask_matches_final_byte
#print axioms all_wire_aliases
#print axioms extra_aliases_fit_iff
#print axioms aliases_distinct
#print axioms raw_limit_is_256_bits

end Abc.Spec.ProviderInputs.X25519
