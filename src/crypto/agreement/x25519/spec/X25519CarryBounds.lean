/-!
Magnitude bounds for the three carry sweeps in the Rust 5×51 representation.
This file models the sweeps as natural-number operations and bounds the
columns from multiplying two bounded limb arrays. It leaves extracted Rust
correspondence, field congruence and the Montgomery ladder to separate proofs.
-/
namespace Abc.Spec.X25519.CarryBounds

def radix : Nat := 2^51

structure Limbs where
  l0 : Nat
  l1 : Nat
  l2 : Nat
  l3 : Nat
  l4 : Nat

def Bounded (x : Limbs) (first rest : Nat) : Prop :=
  x.l0 < first ∧ x.l1 < rest ∧ x.l2 < rest ∧ x.l3 < rest ∧ x.l4 < rest

private theorem radix_pos : 0 < radix := by decide

private def wide1 (x : Limbs) : Nat := x.l1 + x.l0 / radix
private def wide2 (x : Limbs) : Nat := x.l2 + wide1 x / radix
private def wide3 (x : Limbs) : Nat := x.l3 + wide2 x / radix
private def wide4 (x : Limbs) : Nat := x.l4 + wide3 x / radix

def carryColumns (x : Limbs) : Limbs :=
  ⟨x.l0, wide1 x, wide2 x, wide3 x, wide4 x⟩

def sweep (x : Limbs) : Limbs :=
  let wide := carryColumns x
  ⟨wide.l0 % radix + 19 * (wide.l4 / radix), wide.l1 % radix,
    wide.l2 % radix, wide.l3 % radix, wide.l4 % radix⟩

private theorem sweep_bounded {x : Limbs} {limit : Nat}
    (h : x.l0 % radix + 19 * (wide4 x / radix) < limit) :
    Bounded (sweep x) limit radix :=
  ⟨h, Nat.mod_lt _ radix_pos, Nat.mod_lt _ radix_pos,
    Nat.mod_lt _ radix_pos, Nat.mod_lt _ radix_pos⟩

private theorem quotient_lt {x q : Nat} (h : x < q * radix) : x / radix < q :=
  (Nat.div_lt_iff_lt_mul radix_pos).2 h

private theorem wide_with_first_carry {limb previous : Nat}
    (limbBound : limb < 77 * radix * radix) (previousBound : previous < 78 * radix * radix) :
    limb + previous / radix < 78 * radix * radix := by
  have carryBound : previous / radix < 78 * radix := quotient_lt previousBound
  unfold radix at *
  omega

private theorem first_sweep_carry_columns {x : Limbs}
    (bound : Bounded x (77 * radix * radix) (77 * radix * radix)) :
    Bounded (carryColumns x) (78 * radix * radix) (78 * radix * radix) := by
  rcases bound with ⟨h0, h1, h2, h3, h4⟩
  have w0 : x.l0 < 78 * radix * radix := by
    unfold radix at *
    omega
  have w1 : wide1 x < 78 * radix * radix := wide_with_first_carry h1 w0
  have w2 : wide2 x < 78 * radix * radix := wide_with_first_carry h2 w1
  have w3 : wide3 x < 78 * radix * radix := wide_with_first_carry h3 w2
  have w4 : wide4 x < 78 * radix * radix := wide_with_first_carry h4 w3
  exact ⟨w0, w1, w2, w3, w4⟩

private theorem first_sweep {x : Limbs} (bound : Bounded x (77 * radix * radix) (77 * radix * radix)) :
    Bounded (sweep x) (1483 * radix) radix := by
  have w4 : wide4 x < 78 * radix * radix := (first_sweep_carry_columns bound).2.2.2.2
  have top : wide4 x / radix < 78 * radix := quotient_lt w4
  have low := Nat.mod_lt x.l0 radix_pos
  apply sweep_bounded
  unfold radix at *
  omega

private theorem bounded_mono {x : Limbs} {a b c d : Nat}
    (bound : Bounded x a b) (ha : a ≤ c) (hb : b ≤ d) : Bounded x c d := by
  rcases bound with ⟨h0, h1, h2, h3, h4⟩
  exact ⟨Nat.lt_of_lt_of_le h0 ha, Nat.lt_of_lt_of_le h1 hb, Nat.lt_of_lt_of_le h2 hb,
    Nat.lt_of_lt_of_le h3 hb, Nat.lt_of_lt_of_le h4 hb⟩

theorem sweep_fits_u128 (x : Limbs)
    (bound : Bounded x (77 * radix * radix) (77 * radix * radix)) :
    Bounded (carryColumns x) (2^128) (2^128) ∧ Bounded (sweep x) (2^128) (2^128) := by
  exact ⟨bounded_mono (first_sweep_carry_columns bound) (by decide) (by decide),
    bounded_mono (first_sweep bound) (by decide) (by decide)⟩

private theorem wide_with_one_carry {limb previous : Nat}
    (limbBound : limb < radix) (previousBound : previous < 2 * radix) :
    limb + previous / radix < 2 * radix := by
  have carryBound : previous / radix < 2 := quotient_lt previousBound
  unfold radix at *
  omega

private theorem top_carry_at_most_one {x : Limbs} (bound : Bounded x (1483 * radix) radix) :
    wide4 x / radix < 2 := by
  rcases bound with ⟨h0, h1, h2, h3, h4⟩
  have carry0 : x.l0 / radix < 1483 := quotient_lt h0
  have w1 : wide1 x < 2 * radix := by
    unfold wide1
    unfold radix at *
    omega
  have w2 : wide2 x < 2 * radix := wide_with_one_carry h2 w1
  have w3 : wide3 x < 2 * radix := wide_with_one_carry h3 w2
  have w4 : wide4 x < 2 * radix := wide_with_one_carry h4 w3
  exact quotient_lt w4

private theorem second_sweep {x : Limbs} (bound : Bounded x (1483 * radix) radix) :
    Bounded (sweep x) (radix + 19) radix := by
  have top := top_carry_at_most_one bound
  have low := Nat.mod_lt x.l0 radix_pos
  apply sweep_bounded
  omega

private theorem third_sweep {x : Limbs} (bound : Bounded x (radix + 19) radix) :
    Bounded (sweep x) radix radix := by
  rcases bound with ⟨h0, h1, h2, h3, h4⟩
  apply sweep_bounded
  by_cases low : x.l0 < radix
  · have c0 := Nat.div_eq_of_lt low
    have c1 : wide1 x / radix = 0 := by
      simpa [wide1, c0] using Nat.div_eq_of_lt h1
    have c2 : wide2 x / radix = 0 := by
      simpa [wide2, c1] using Nat.div_eq_of_lt h2
    have c3 : wide3 x / radix = 0 := by
      simpa [wide3, c2] using Nat.div_eq_of_lt h3
    have c4 : wide4 x / radix = 0 := by
      simpa [wide4, c3] using Nat.div_eq_of_lt h4
    simpa [c4] using Nat.mod_lt x.l0 radix_pos
  · have large : Bounded x (1483 * radix) radix := by
      refine ⟨?_, h1, h2, h3, h4⟩
      unfold radix at *
      omega
    have top := top_carry_at_most_one large
    have h0Wide : x.l0 < 2 * radix := by
      unfold radix at *
      omega
    have c0Upper : x.l0 / radix < 2 := quotient_lt h0Wide
    have c0Lower : 1 ≤ x.l0 / radix := (Nat.le_div_iff_mul_le radix_pos).2 (by simpa using Nat.le_of_not_gt low)
    have c0 : x.l0 / radix = 1 := by omega
    have decomposition := Nat.mod_add_div x.l0 radix
    rw [c0, Nat.mul_one] at decomposition
    unfold radix at *
    omega

theorem reduce_three_sweeps (x : Limbs)
    (bound : Bounded x (77 * radix * radix) (77 * radix * radix)) :
    Bounded (sweep (sweep (sweep x))) radix radix :=
  third_sweep (second_sweep (first_sweep bound))

/- The weighted convolution used before the sweeps. A product above limb four
folds into its lower column with weight 19. -/
def mulColumns (a b : Limbs) : Limbs :=
  ⟨a.l0 * b.l0 + 19 * (a.l1 * b.l4 + a.l2 * b.l3 + a.l3 * b.l2 + a.l4 * b.l1),
    a.l0 * b.l1 + a.l1 * b.l0 + 19 * (a.l2 * b.l4 + a.l3 * b.l3 + a.l4 * b.l2),
    a.l0 * b.l2 + a.l1 * b.l1 + a.l2 * b.l0 + 19 * (a.l3 * b.l4 + a.l4 * b.l3),
    a.l0 * b.l3 + a.l1 * b.l2 + a.l2 * b.l1 + a.l3 * b.l0 + 19 * (a.l4 * b.l4),
    a.l0 * b.l4 + a.l1 * b.l3 + a.l2 * b.l2 + a.l3 * b.l1 + a.l4 * b.l0⟩

private theorem mul_lt_radix_squared {a b : Nat} (ha : a < radix) (hb : b < radix) :
    a * b < radix * radix :=
  Nat.lt_of_le_of_lt (Nat.mul_le_mul_left a (Nat.le_of_lt hb))
    (Nat.mul_lt_mul_of_pos_right ha radix_pos)

theorem mul_columns_bounded (a b : Limbs) (ha : Bounded a radix radix) (hb : Bounded b radix radix) :
    Bounded (mulColumns a b) (77 * radix * radix) (77 * radix * radix) := by
  rcases ha with ⟨a0, a1, a2, a3, a4⟩
  rcases hb with ⟨b0, b1, b2, b3, b4⟩
  simp only [Bounded, mulColumns]
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · have h00 := mul_lt_radix_squared a0 b0
    have h14 := mul_lt_radix_squared a1 b4
    have h23 := mul_lt_radix_squared a2 b3
    have h32 := mul_lt_radix_squared a3 b2
    have h41 := mul_lt_radix_squared a4 b1
    unfold radix at *
    omega
  · have h01 := mul_lt_radix_squared a0 b1
    have h10 := mul_lt_radix_squared a1 b0
    have h24 := mul_lt_radix_squared a2 b4
    have h33 := mul_lt_radix_squared a3 b3
    have h42 := mul_lt_radix_squared a4 b2
    unfold radix at *
    omega
  · have h02 := mul_lt_radix_squared a0 b2
    have h11 := mul_lt_radix_squared a1 b1
    have h20 := mul_lt_radix_squared a2 b0
    have h34 := mul_lt_radix_squared a3 b4
    have h43 := mul_lt_radix_squared a4 b3
    unfold radix at *
    omega
  · have h03 := mul_lt_radix_squared a0 b3
    have h12 := mul_lt_radix_squared a1 b2
    have h21 := mul_lt_radix_squared a2 b1
    have h30 := mul_lt_radix_squared a3 b0
    have h44 := mul_lt_radix_squared a4 b4
    unfold radix at *
    omega
  · have h04 := mul_lt_radix_squared a0 b4
    have h13 := mul_lt_radix_squared a1 b3
    have h22 := mul_lt_radix_squared a2 b2
    have h31 := mul_lt_radix_squared a3 b1
    have h40 := mul_lt_radix_squared a4 b0
    unfold radix at *
    omega

theorem mul_reduced_limbs (a b : Limbs) (ha : Bounded a radix radix) (hb : Bounded b radix radix) :
    Bounded (sweep (sweep (sweep (mulColumns a b)))) radix radix :=
  reduce_three_sweeps (mulColumns a b) (mul_columns_bounded a b ha hb)

#print axioms reduce_three_sweeps
#print axioms sweep_fits_u128
#print axioms mul_columns_bounded
#print axioms mul_reduced_limbs

end Abc.Spec.X25519.CarryBounds
