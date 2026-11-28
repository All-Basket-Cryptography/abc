namespace Abc.Spec.Scrypt.CSharp

def maxArrayBytes : Nat := 2 ^ 31 - 65

theorem checked_product (stride count : Nat) (positive : 0 < count)
    (guard : stride ≤ maxArrayBytes / count) : stride * count ≤ maxArrayBytes :=
  (Nat.le_div_iff_mul_le positive).mp guard

theorem memory_limit_comparison_fits (work output : Nat)
    (workCap : work ≤ maxArrayBytes) (outputCap : output ≤ maxArrayBytes) :
    work + output < 2 ^ 32 := by
  unfold maxArrayBytes at *
  omega

theorem lane_word_inside_slice (wordCount index : Nat) (valid : index < wordCount) :
    index * 4 + 4 ≤ wordCount * 4 := by
  omega

theorem slot_end_fits_signed_index (slots stride slot : Nat)
    (table : slots * stride ≤ maxArrayBytes) (valid : slot < slots) :
    (slot + 1) * stride < 2 ^ 31 := by
  have inside := Nat.mul_le_mul_right stride (show slot + 1 ≤ slots by omega)
  unfold maxArrayBytes at table
  omega

#print axioms checked_product
#print axioms memory_limit_comparison_fits
#print axioms lane_word_inside_slice
#print axioms slot_end_fits_signed_index

end Abc.Spec.Scrypt.CSharp
