import Init.Data.BitVec

namespace Abc.Spec.Aes256Gcm

abbrev Byte := BitVec 8

def tagDifference : List (Byte × Byte) → Byte
  | [] => 0
  | (a, b) :: tail => (a ^^^ b) ||| tagDifference tail

theorem tag_difference_zero_iff (pairs : List (Byte × Byte)) :
    tagDifference pairs = 0 ↔ ∀ pair ∈ pairs, pair.1 = pair.2 := by
  induction pairs with
  | nil => simp [tagDifference]
  | cons pair tail ih =>
    obtain ⟨a, b⟩ := pair
    change ((a ^^^ b) ||| tagDifference tail) = 0#8 ↔ _
    rw [BitVec.or_eq_zero_iff, BitVec.xor_eq_zero_iff]
    simp only [List.mem_cons]
    constructor
    · intro h other member
      rcases member with equal | contained
      · cases equal
        exact h.1
      · exact ih.mp h.2 other contained
    · intro h
      exact ⟨h (a, b) (.inl rfl), ih.mpr fun pair contained => h pair (.inr contained)⟩

theorem payload_counter_range (length index : Nat)
    (lengthLimit : length ≤ (2^32 - 2) * 16) (block : index < (length + 15) / 16) :
    1 < index + 2 ∧ index + 2 < 2^32 := by
  omega

#print axioms tag_difference_zero_iff
#print axioms payload_counter_range

end Abc.Spec.Aes256Gcm
