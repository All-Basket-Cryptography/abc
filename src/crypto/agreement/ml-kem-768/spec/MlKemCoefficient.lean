import Std

namespace Abc.Spec.MlKem.Coefficient

def q : Nat := 3329
def scale (width : Nat) : Nat := 2^width

def roundHalfUp (numerator denominator : Nat) : Nat :=
  if 2 * (numerator % denominator) < denominator then numerator / denominator
  else numerator / denominator + 1

theorem round_integer_eq_half_up (numerator denominator : Nat) (positive : 0 < denominator) :
    (numerator + denominator / 2) / denominator = roundHalfUp numerator denominator := by
  have remainderBound := Nat.mod_lt numerator positive
  have sum : numerator + denominator / 2 =
      (numerator % denominator + denominator / 2) + denominator * (numerator / denominator) := by
    rw [Nat.add_right_comm, Nat.mod_add_div]
  rw [sum, Nat.add_mul_div_left _ _ positive]
  unfold roundHalfUp
  split
  · rw [Nat.div_eq_of_lt (by omega), Nat.zero_add]
  · rw [Nat.div_eq_sub_div positive (by omega), Nat.div_eq_of_lt (by omega)]
    omega

private def roundedCoefficient (width coefficient : Nat) : Nat :=
  (scale width * coefficient + q / 2) / q

def compress (width coefficient : Nat) : Nat :=
  roundedCoefficient width coefficient % scale width

def decompress (width code : Nat) : Nat :=
  (q * code + scale width / 2) / scale width

theorem compress_eq_rounding (width coefficient : Nat) :
    compress width coefficient = roundHalfUp (scale width * coefficient) q % scale width := by
  unfold compress roundedCoefficient
  rw [round_integer_eq_half_up _ _ (by decide)]

theorem decompress_eq_rounding (width code : Nat) :
    decompress width code = roundHalfUp (q * code) (scale width) := by
  unfold decompress
  exact round_integer_eq_half_up _ _ (show 0 < scale width from Nat.pow_pos (by decide))

theorem compress_no_half_tie (width coefficient : Nat) :
    2 * (scale width * coefficient % q) ≠ q := by
  unfold q
  omega

theorem compress_range (width coefficient : Nat) : compress width coefficient < scale width := by
  exact Nat.mod_lt _ (Nat.pow_pos (by decide))

private theorem scale_limit (width : Nat) (widthBound : width < 12) : scale width ≤ 2048 := by
  exact Nat.pow_le_pow_right (by decide) (show width ≤ 11 by omega)

theorem decompress_range (width code : Nat) (widthBound : width < 12)
    (codeBound : code < scale width) : decompress width code < q := by
  have scaleBound := scale_limit width widthBound
  unfold decompress
  apply (Nat.div_lt_iff_lt_mul (show 0 < scale width from Nat.pow_pos (by decide))).mpr
  unfold q
  omega

theorem recompress_decompressed (width code : Nat) (widthBound : width < 12)
    (codeBound : code < scale width) : compress width (decompress width code) = code := by
  let widthScale := scale width
  have scaleBound : widthScale ≤ 2048 := scale_limit width widthBound
  have scalePositive : 0 < widthScale := Nat.pow_pos (by decide)
  have divRem := Nat.mod_add_div (q * code + widthScale / 2) widthScale
  have remainderBound := Nat.mod_lt (q * code + widthScale / 2) scalePositive
  have exactQuotient :
      (widthScale * ((q * code + widthScale / 2) / widthScale) + q / 2) / q = code := by
    unfold q at *
    omega
  change ((widthScale * ((q * code + widthScale / 2) / widthScale) + q / 2) / q) % widthScale = code
  rw [exactQuotient, Nat.mod_eq_of_lt codeBound]

def encodeCode (width coefficient : Nat) : BitVec width :=
  BitVec.ofNat width (compress width coefficient)

theorem encoded_value (width coefficient : Nat) :
    (encodeCode width coefficient).toNat = compress width coefficient := by
  exact Nat.mod_eq_of_lt (compress_range width coefficient)

theorem normalized_wire_code (width : Nat) (wire : BitVec width) (widthBound : width < 12) :
    encodeCode width (decompress width wire.toNat) = wire := by
  apply BitVec.eq_of_toNat_eq
  rw [encoded_value, recompress_decompressed width _ widthBound wire.isLt]

theorem decompress4_tie (code : Nat) (valid : code < 16) :
    2 * (q * code % scale 4) = scale 4 ↔ code = 8 := by
  simp only [q, scale]
  omega

theorem decompress10_tie (code : Nat) (valid : code < 1024) :
    2 * (q * code % scale 10) = scale 10 ↔ code = 512 := by
  simp only [q, scale]
  omega

theorem decompress_midpoints_round_up :
    decompress 4 8 = 1665 ∧ decompress 10 512 = 1665 := by
  decide +kernel

def circularDistance (left right : Nat) : Nat :=
  let difference := (left - right) + (right - left)
  min difference (q - difference)

private theorem decompress_at_width (width : Nat) : decompress width (scale width) = q := by
  have scalePositive : 0 < scale width := Nat.pow_pos (by decide)
  unfold decompress
  rw [Nat.mul_comm, Nat.add_comm, Nat.add_mul_div_left _ _ scalePositive,
    Nat.div_eq_of_lt (by omega), Nat.zero_add]

-- The rounding quotient can land at the circle endpoint. Before reduction
-- that point reconstructs to q, while its canonical wire value reconstructs to zero.
private theorem circularDistance_from_rounding (width coefficient radius : Nat)
    (quotient : roundedCoefficient width coefficient ≤ scale width)
    (lower : coefficient ≤ decompress width (roundedCoefficient width coefficient) + radius)
    (upper : decompress width (roundedCoefficient width coefficient) ≤ coefficient + radius) :
    circularDistance coefficient (decompress width (compress width coefficient)) ≤ radius := by
  by_cases wrapped : roundedCoefficient width coefficient = scale width
  · rw [wrapped, decompress_at_width] at upper
    unfold compress
    rw [wrapped, Nat.mod_self]
    have zeroCode : decompress width 0 = 0 := by
      unfold decompress
      rw [Nat.mul_zero, Nat.zero_add, Nat.div_eq_of_lt]
      have scalePositive : 0 < scale width := Nat.pow_pos (by decide)
      omega
    rw [zeroCode]
    unfold circularDistance
    dsimp only
    apply Nat.le_trans (Nat.min_le_right _ _)
    omega
  · have canonical : roundedCoefficient width coefficient < scale width := by omega
    unfold compress
    rw [Nat.mod_eq_of_lt canonical]
    unfold circularDistance
    dsimp only
    apply Nat.le_trans (Nat.min_le_left _ _)
    omega

theorem quantization_error_bound (width coefficient : Nat) (valid : coefficient < q) :
    circularDistance coefficient (decompress width (compress width coefficient)) ≤
      (q / 2 + scale width / 2) / scale width := by
  let widthScale := scale width
  let rounded := roundedCoefficient width coefficient
  let reconstructed := decompress width rounded
  have scalePositive : 0 < widthScale := Nat.pow_pos (by decide)
  have inField := Nat.mul_le_mul_left widthScale (show coefficient ≤ q - 1 by omega)
  have unwrapped : rounded ≤ widthScale := by
    change (widthScale * coefficient + q / 2) / q ≤ widthScale
    simp only [q] at *
    rw [Nat.mul_comm widthScale 3328] at inField
    omega
  have compressRem := Nat.mod_add_div (widthScale * coefficient + q / 2) q
  change (widthScale * coefficient + q / 2) % q + q * rounded =
    widthScale * coefficient + q / 2 at compressRem
  have compressBound := Nat.mod_lt (widthScale * coefficient + q / 2) (show 0 < q by decide)
  have decompressRem := Nat.mod_add_div (q * rounded + widthScale / 2) widthScale
  change (q * rounded + widthScale / 2) % widthScale + widthScale * reconstructed =
    q * rounded + widthScale / 2 at decompressRem
  have decompressBound := Nat.mod_lt (q * rounded + widthScale / 2) scalePositive
  have rescaledLower : widthScale * coefficient ≤ widthScale * reconstructed + (q / 2 + widthScale / 2) := by
    simp only [q] at *
    omega
  have rescaledUpper : widthScale * reconstructed ≤ widthScale * coefficient + (q / 2 + widthScale / 2) := by
    simp only [q] at *
    omega
  have lower : coefficient - reconstructed ≤ (q / 2 + widthScale / 2) / widthScale := by
    apply (Nat.le_div_iff_mul_le scalePositive).mpr
    rw [Nat.sub_mul, Nat.mul_comm coefficient, Nat.mul_comm reconstructed]
    omega
  have upper : reconstructed - coefficient ≤ (q / 2 + widthScale / 2) / widthScale := by
    apply (Nat.le_div_iff_mul_le scalePositive).mpr
    rw [Nat.sub_mul, Nat.mul_comm reconstructed, Nat.mul_comm coefficient]
    omega
  apply circularDistance_from_rounding _ _ _ unwrapped
  · change coefficient ≤ reconstructed + (q / 2 + widthScale / 2) / widthScale
    omega
  · change reconstructed ≤ coefficient + (q / 2 + widthScale / 2) / widthScale
    omega

theorem compress4_error_bound (coefficient : Nat) (valid : coefficient < q) :
    circularDistance coefficient (decompress 4 (compress 4 coefficient)) ≤ 104 := by
  exact quantization_error_bound 4 coefficient valid

theorem compress10_error_bound (coefficient : Nat) (valid : coefficient < q) :
    circularDistance coefficient (decompress 10 (compress 10 coefficient)) ≤ 2 := by
  exact quantization_error_bound 10 coefficient valid

theorem error_bounds_are_sharp :
    circularDistance 104 (decompress 4 (compress 4 104)) = 104 ∧
      circularDistance 5 (decompress 10 (compress 10 5)) = 2 := by
  decide +kernel

#print axioms round_integer_eq_half_up
#print axioms compress_eq_rounding
#print axioms decompress_eq_rounding
#print axioms compress_no_half_tie
#print axioms compress_range
#print axioms decompress_range
#print axioms recompress_decompressed
#print axioms encoded_value
#print axioms normalized_wire_code
#print axioms decompress4_tie
#print axioms decompress10_tie
#print axioms decompress_midpoints_round_up
#print axioms quantization_error_bound
#print axioms compress4_error_bound
#print axioms compress10_error_bound
#print axioms error_bounds_are_sharp

end Abc.Spec.MlKem.Coefficient
