namespace Abc.Spec.MlDsa65.Jvm

def hintOffset : Nat := 3309 - 55 - 6

theorem hint_index_inside_signature (j : Nat) (bound : j < 55) :
    hintOffset + j < hintOffset + 55 ∧ hintOffset + j < 3309 := by
  unfold hintOffset
  omega

theorem delimiter_after_indices (j : Nat) (bound : j < 6) :
    hintOffset + 55 ≤ hintOffset + 55 + j ∧ hintOffset + 55 + j < 3309 := by
  unfold hintOffset
  omega

theorem admitted_slice_inside_hint_indices (start stop i : Nat)
    (lower : start ≤ i) (upper : i < stop) (maxHints : stop ≤ 55) :
    i < 55 ∧ hintOffset + i < hintOffset + 55 := by
  omega

theorem hint_order_implies_unique (indices : List Nat)
    (ordered : indices.Pairwise (· < ·)) : indices.Nodup := by
  exact ordered.imp (fun h => Nat.ne_of_lt h)

theorem admitted_context_length_fits_byte (n : Nat) (bound : n ≤ 255) : n < 256 := by omega

#print axioms hint_index_inside_signature
#print axioms delimiter_after_indices
#print axioms admitted_slice_inside_hint_indices
#print axioms hint_order_implies_unique
#print axioms admitted_context_length_fits_byte

end Abc.Spec.MlDsa65.Jvm
