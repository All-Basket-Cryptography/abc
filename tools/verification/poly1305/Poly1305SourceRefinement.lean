import Abc.Poly1305.Extracted.Funs
import Poly1305GoModel

namespace Abc.Refine.Poly1305

open Aeneas Aeneas.Std
open Aeneas.Std.Result
open Abc.Poly1305.Extracted
open Abc.Spec.Poly1305.Go (Columns base bounded live value modulus productColumns carry_keeps_live
  product_columns_fit added_block_fits addColumns absorb_fits absorb_value polynomialStep)

set_option maxHeartbeats 4500000
set_option maxRecDepth 4096

private abbrev Words := Aeneas.Std.Array U64 5#usize
private abbrev Multiples := Aeneas.Std.Array U64 4#usize

def columns (a : Words) : Columns :=
  ⟨a.val[0]!.val, a.val[1]!.val, a.val[2]!.val, a.val[3]!.val, a.val[4]!.val⟩

def cachedMultiples (r : Words) (rFive : Multiples) : Prop :=
  rFive.val[0]!.val = 5 * r.val[1]!.val ∧ rFive.val[1]!.val = 5 * r.val[2]!.val ∧
  rFive.val[2]!.val = 5 * r.val[3]!.val ∧ rFive.val[3]!.val = 5 * r.val[4]!.val

private theorem index_word {n : Usize} (a : Aeneas.Std.Array U64 n) (i : Usize)
    (bound : i.val < n.val) : a.index_usize i = .ok a.val[i.val]! := by
  have within : i.val < a.val.length := by simpa using bound
  simp [Aeneas.Std.Array.index_usize, Aeneas.Std.Array.getElem?_Usize_eq, getElem?_pos a.val i.val within]

private theorem index0 {n : Usize} (a : Aeneas.Std.Array U64 n) (bound : 0 < n.val) :
    a.index_usize 0#usize = .ok a.val[0]! := by
  simpa only [show (0#usize).val = 0 by decide] using index_word a 0#usize bound

private theorem index1 {n : Usize} (a : Aeneas.Std.Array U64 n) (bound : 1 < n.val) :
    a.index_usize 1#usize = .ok a.val[1]! := by
  simpa only [show (1#usize).val = 1 by decide] using index_word a 1#usize bound

private theorem index2 {n : Usize} (a : Aeneas.Std.Array U64 n) (bound : 2 < n.val) :
    a.index_usize 2#usize = .ok a.val[2]! := by
  simpa only [show (2#usize).val = 2 by decide] using index_word a 2#usize bound

private theorem index3 {n : Usize} (a : Aeneas.Std.Array U64 n) (bound : 3 < n.val) :
    a.index_usize 3#usize = .ok a.val[3]! := by
  simpa only [show (3#usize).val = 3 by decide] using index_word a 3#usize bound

private theorem index4 {n : Usize} (a : Aeneas.Std.Array U64 n) (bound : 4 < n.val) :
    a.index_usize 4#usize = .ok a.val[4]! := by
  simpa only [show (4#usize).val = 4 by decide] using index_word a 4#usize bound

private def natWord (n : Nat) : U64 := ⟨BitVec.ofNat 64 n⟩

private theorem natWord_val (n : Nat) (fits : n < 2^64) : (natWord n).val = n := by
  change (BitVec.ofNat 64 n).toNat = n
  rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt fits]

private theorem mul_word (a b : U64) (fits : a.val * b.val < 2^64) :
    (a * b : Result U64) = .ok (natWord (a.val * b.val)) := by
  have bound : a.val * b.val ≤ UScalar.max .U64 := by scalar_tac
  obtain ⟨out, result, exactVal⟩ := WP.spec_imp_exists (UScalar.mul_spec bound)
  rw [result, UScalar.eq_of_val_eq (exactVal.trans (natWord_val _ fits).symm)]

private theorem add_word (a b : U64) (fits : a.val + b.val < 2^64) :
    (a + b : Result U64) = .ok (natWord (a.val + b.val)) := by
  have bound : a.val + b.val ≤ UScalar.max .U64 := by scalar_tac
  obtain ⟨out, result, exactVal⟩ := WP.spec_imp_exists (UScalar.add_spec bound)
  rw [result, UScalar.eq_of_val_eq (exactVal.trans (natWord_val _ fits).symm)]

private theorem add_natWord (a b : Nat) (fits : a + b < 2^64) :
    (natWord a + natWord b : Result U64) = .ok (natWord (a + b)) := by
  have av : (natWord a).val = a := natWord_val a (by omega)
  have bv : (natWord b).val = b := natWord_val b (by omega)
  rw [add_word _ _ (by simpa only [av, bv] using fits), av, bv]

private theorem mul_five (a : U64) (fits : a.val * 5 < 2^64) :
    (a * 5#u64 : Result U64) = .ok (natWord (a.val * 5)) := by
  exact mul_word a 5#u64 fits

private theorem product_bound (a b : U64) (ha : a.val < 201326592) (hb : b.val < 335544320) :
    a.val * b.val < 2^56 := by
  have upper := Nat.mul_le_mul (Nat.le_of_lt ha) (Nat.le_of_lt hb)
  omega

/-- The cached products derived by the actual constructor's helper are exact. -/
theorem source_key_multiples_refines (r : Words) (keyBound : bounded (columns r) base) :
    key_multiples r ⦃ out => cachedMultiples r out ⦄ := by
  simp only [bounded, columns, base] at keyBound
  rcases keyBound with ⟨_, r1, r2, r3, r4⟩
  simp (disch := decide) only [key_multiples, index1, index2, index3, index4, Aeneas.Std.bind_tc_ok]
  simp (disch := omega) only [mul_five, Aeneas.Std.bind_tc_ok, WP.spec_ok,
    cachedMultiples, Aeneas.Std.Array.make_val, List.getElem!_cons_zero,
    List.getElem!_cons_succ, natWord_val]
  omega

/-- The exact extracted 25 products and their additions are defined within
the reachable bounds. All five resulting columns equal the natural-number
folded convolution of the two radix-26 inputs. -/
theorem source_multiply_refines (h r : Words) (rFive : Multiples)
    (hBound : bounded (columns h) (3 * base))
    (rBound : bounded (columns r) base) (cache : cachedMultiples r rFive) :
    multiply h r rFive ⦃ out => columns out = productColumns (columns h) (columns r) ⦄ := by
  simp only [bounded, columns, base] at hBound rBound
  rcases hBound with ⟨h0Bound, h1Bound, h2Bound, h3Bound, h4Bound⟩
  rcases rBound with ⟨r0Bound, r1Bound, r2Bound, r3Bound, r4Bound⟩
  rcases cache with ⟨cache1, cache2, cache3, cache4⟩
  have f0 : rFive.val[0]!.val < 335544320 := by omega
  have f1 : rFive.val[1]!.val < 335544320 := by omega
  have f2 : rFive.val[2]!.val < 335544320 := by omega
  have f3 : rFive.val[3]!.val < 335544320 := by omega
  have term00 := product_bound h.val[0]! r.val[0]! h0Bound (by omega)
  have term01 := product_bound h.val[0]! r.val[1]! h0Bound (by omega)
  have term02 := product_bound h.val[0]! r.val[2]! h0Bound (by omega)
  have term03 := product_bound h.val[0]! r.val[3]! h0Bound (by omega)
  have term04 := product_bound h.val[0]! r.val[4]! h0Bound (by omega)
  have term10 := product_bound h.val[1]! r.val[0]! h1Bound (by omega)
  have term11 := product_bound h.val[1]! r.val[1]! h1Bound (by omega)
  have term12 := product_bound h.val[1]! r.val[2]! h1Bound (by omega)
  have term13 := product_bound h.val[1]! r.val[3]! h1Bound (by omega)
  have term14 := product_bound h.val[1]! rFive.val[3]! h1Bound (f3)
  have term20 := product_bound h.val[2]! r.val[0]! h2Bound (by omega)
  have term21 := product_bound h.val[2]! r.val[1]! h2Bound (by omega)
  have term22 := product_bound h.val[2]! r.val[2]! h2Bound (by omega)
  have term23 := product_bound h.val[2]! rFive.val[2]! h2Bound (f2)
  have term24 := product_bound h.val[2]! rFive.val[3]! h2Bound (f3)
  have term30 := product_bound h.val[3]! r.val[0]! h3Bound (by omega)
  have term31 := product_bound h.val[3]! r.val[1]! h3Bound (by omega)
  have term32 := product_bound h.val[3]! rFive.val[1]! h3Bound (f1)
  have term33 := product_bound h.val[3]! rFive.val[2]! h3Bound (f2)
  have term34 := product_bound h.val[3]! rFive.val[3]! h3Bound (f3)
  have term40 := product_bound h.val[4]! r.val[0]! h4Bound (by omega)
  have term41 := product_bound h.val[4]! rFive.val[0]! h4Bound (f0)
  have term42 := product_bound h.val[4]! rFive.val[1]! h4Bound (f1)
  have term43 := product_bound h.val[4]! rFive.val[2]! h4Bound (f2)
  have term44 := product_bound h.val[4]! rFive.val[3]! h4Bound (f3)
  simp (disch := decide) only [multiply, index0, index1, index2, index3, index4, Aeneas.Std.bind_tc_ok]
  simp (disch := omega) only [mul_word, add_natWord, Aeneas.Std.bind_tc_ok, natWord_val,
    WP.spec_ok, columns, Aeneas.Std.Array.make_val, List.getElem!_cons_zero, List.getElem!_cons_succ]
  simp only [productColumns, cache1, cache2, cache3, cache4]

private theorem limb_mask_exact : LIMB_MASK = .ok 67108863#u64 := by
  have shift : (1#u64 <<< 26#u32) = .ok 67108864#u64 := by rfl
  rw [LIMB_MASK, RADIX_BITS, shift, Aeneas.Std.bind_tc_ok]
  have valid : (1#u64).val ≤ (67108864#u64).val := by decide
  obtain ⟨out, result, exactVal⟩ := WP.spec_imp_exists (UScalar.sub_spec valid)
  rw [result]
  have mask : out = 67108863#u64 := UScalar.eq_of_val_eq (by simpa using exactVal)
  rw [mask]

private theorem low_bits (word : U64) : (word &&& 67108863#u64).val = word.val % base := by
  change (word.bv &&& 67108863#64).toNat = word.val % base
  rw [BitVec.toNat_and]
  change word.val &&& (2^26 - 1) = word.val % 2^26
  exact Nat.and_two_pow_sub_one_eq_mod _ _

private theorem shift26 (word : U64) :
    (word >>> 26#u32) = .ok (⟨word.bv.ushiftRight 26⟩ : U64) := by
  rfl

private theorem shift26_value (word : U64) :
    (⟨word.bv.ushiftRight 26⟩ : U64).val = word.val / base := by
  change (word.bv >>> 26).toNat = word.val / 2^26
  rw [BitVec.toNat_ushiftRight, Nat.shiftRight_eq_div_pow]
  rfl

/-- The source carries the radix quotient and retains the radix remainder. -/
theorem source_carry_pair_refines (low high : U64) (fits : high.val + low.val / base < 2^64) :
    carry_pair low high ⦃ out => out.1.val = low.val % base ∧ out.2.val = high.val + low.val / base ⦄ := by
  have fitsWord : high.val + (⟨low.bv.ushiftRight 26⟩ : U64).val < 2^64 :=
    by simpa only [shift26_value] using fits
  simp only [carry_pair, limb_mask_exact, RADIX_BITS, lift, Aeneas.Std.bind_tc_ok, shift26,
    add_word _ _ fitsWord, WP.spec_ok, low_bits, shift26_value, natWord_val _ fits, and_self]

private def upperCarry (d : Columns) : Columns :=
  let c2 := d.c2 + d.c1 / base
  let c3 := d.c3 + c2 / base
  let c4 := d.c4 + c3 / base
  let low := d.c0 + 5 * (c4 / base)
  ⟨low % base, d.c1 % base + low / base, c2 % base, c3 % base, c4 % base⟩

/-- Carry propagation through the upper limbs and folding of the top carry
agree with the unbounded radix formula on all input columns below 60 bits. -/
theorem source_carry_upper_refines (d : Words) (fits : bounded (columns d) (2^60)) :
    carry_upper d ⦃ out => columns out = upperCarry (columns d) ⦄ := by
  simp only [bounded, columns] at fits
  rcases fits with ⟨f0, f1, f2, f3, f4⟩
  simp (disch := decide) only [carry_upper, index0, index1, index2, index3, index4, Aeneas.Std.bind_tc_ok]
  step with (source_carry_pair_refines d.val[1]! d.val[2]! (by simp only [base]; omega))
    as ⟨low1, col2, w1, w2⟩
  have col2Fit : col2.val < 2^61 := by simp only [base] at w2; omega
  step with (source_carry_pair_refines col2 d.val[3]! (by simp only [base]; omega))
    as ⟨low2, col3, w22, w3⟩
  have col3Fit : col3.val < 2^61 := by simp only [base] at w3; omega
  step with (source_carry_pair_refines col3 d.val[4]! (by simp only [base]; omega))
    as ⟨low3, col4, w33, w4⟩
  have col4Fit : col4.val < 2^61 := by simp only [base] at w4; omega
  simp only [RADIX_BITS, shift26, Aeneas.Std.bind_tc_ok]
  have shifted := shift26_value col4
  have foldFits : (⟨col4.bv.ushiftRight 26⟩ : U64).val * (5#u64).val ≤ UScalar.max .U64 := by
    rw [shifted]
    simp only [base, show (5#u64).val = 5 by decide, UScalar.max_UScalarTy_U64_eq, U64.max_eq]
    omega
  step with (UScalar.mul_spec foldFits) as ⟨folded, foldedEq⟩
  have foldedVal : folded.val = (col4.val / base) * 5 := by
    simpa only [shifted, show (5#u64).val = 5 by decide] using foldedEq
  have sumFits : d.val[0]!.val + folded.val ≤ UScalar.max .U64 := by
    simp only [foldedVal, base, UScalar.max_UScalarTy_U64_eq, U64.max_eq]
    omega
  step with (UScalar.add_spec sumFits) as ⟨newLow, newLowEq⟩
  have lower : low1.val < base := by rw [w1]; exact Nat.mod_lt _ (by decide)
  have newLowBound : newLow.val < 2^61 := by
    simp only [foldedVal, base] at newLowEq
    omega
  simp only [limb_mask_exact, lift, Aeneas.Std.bind_tc_ok]
  step with (source_carry_pair_refines newLow low1 (by simp only [base] at lower ⊢; omega))
    as ⟨low0, final1, w0, w11⟩
  have newLowValue : newLow.val = d.val[0]!.val + 5 * (col4.val / base) := by
    omega
  simp only [columns, upperCarry, Aeneas.Std.Array.make_val, List.getElem!_cons_zero,
    List.getElem!_cons_succ, low_bits, w0, w11, w1, w22, w33, newLowValue, w4, w3, w2]

/-- The exact carry path reduces convolution columns without overflow and
returns the same limb state as the mathematical carry function. -/
theorem source_carry_refines (d : Words) (fits : bounded (columns d) (2^59)) :
    carry d ⦃ out => columns out = Abc.Spec.Poly1305.Go.carry (columns d) ⦄ := by
  simp only [bounded, columns] at fits
  rcases fits with ⟨f0, f1, f2, f3, f4⟩
  simp (disch := decide) only [carry, index0, index1, index2, index3, index4, Aeneas.Std.bind_tc_ok]
  step with (source_carry_pair_refines d.val[0]! d.val[1]! (by simp only [base]; omega))
    as ⟨low0, col1, w0, w1⟩
  have nextBound : bounded (columns (Aeneas.Std.Array.make 5#usize
      [low0, col1, d.val[2]!, d.val[3]!, d.val[4]!])) (2^60) := by
    simp only [bounded, columns, Aeneas.Std.Array.make_val, List.getElem!_cons_zero,
      List.getElem!_cons_succ, w0, w1, base]
    omega
  step with (source_carry_upper_refines _ nextBound) as ⟨out, exactCols⟩
  rw [exactCols]
  simp only [upperCarry, Abc.Spec.Poly1305.Go.carry, Abc.Spec.Poly1305.Go.sweep, columns,
    Aeneas.Std.Array.make_val, List.getElem!_cons_zero, List.getElem!_cons_succ, w0, w1]

/-- The exact upper-carry call at the beginning of Rust's final reduction
normalizes a live accumulator and preserves its residue. -/
theorem source_final_carry_refines (d : Words) (state : live (columns d)) :
    carry_upper d ⦃ out => bounded (columns out) base ∧
      value (columns out) % modulus = value (columns d) % modulus ⦄ := by
  have fits : bounded (columns d) (2^60) := by
    simp only [live, base] at state
    simp only [bounded]
    omega
  refine WP.spec_mono (source_carry_upper_refines d fits) ?_
  intro out exactCarry
  have low := Nat.div_eq_of_lt state.1
  have unchanged := Nat.mod_eq_of_lt state.1
  have agrees : upperCarry (columns d) = Abc.Spec.Poly1305.Go.carry (columns d) := by
    simp only [upperCarry, Abc.Spec.Poly1305.Go.carry, Abc.Spec.Poly1305.Go.sweep, low, unchanged, Nat.add_zero]
  rw [exactCarry, agrees]
  exact ⟨Abc.Spec.Poly1305.Go.carry_normalizes _ state, Abc.Spec.Poly1305.Go.carry_congruence _⟩

private theorem wrapping_select_zero (x y : U64) : select_reduced x y 0#u64 = .ok x := by
  unfold select_reduced
  simp only [lift, Aeneas.Std.bind_tc_ok]
  apply congrArg Result.ok
  apply UScalar.eq_of_val_eq
  have selected : x.bv &&& ~~~(0#64) ||| y.bv &&& (0#64) = x.bv := by bv_decide
  exact congrArg BitVec.toNat selected

private theorem wrapping_select_ones (x y : U64) : select_reduced x y 18446744073709551615#u64 = .ok y := by
  unfold select_reduced
  simp only [lift, Aeneas.Std.bind_tc_ok]
  apply congrArg Result.ok
  apply UScalar.eq_of_val_eq
  have selected : x.bv &&& ~~~(18446744073709551615#64) |||
      y.bv &&& (18446744073709551615#64) = y.bv := by bv_decide
  exact congrArg BitVec.toNat selected

/-- The exact final reduction returns the unique residue below the prime.
The input fits 130 bits, so the top carry is either zero or one. -/
theorem source_reduce_final_refines (d : Words) (fit : bounded (columns d) base) :
    reduce_final d ⦃ out => bounded (columns out) base ∧
      value (columns out) = value (columns d) % modulus ⦄ := by
  have inputValue := Abc.Spec.Poly1305.Go.normalized_value_bounded _ fit
  have bounds := fit
  simp only [bounded, columns] at bounds
  rcases bounds with ⟨f0, f1, f2, f3, f4⟩
  simp (disch := decide) only [reduce_final, index0, index1, index2, index3, index4, Aeneas.Std.bind_tc_ok]
  have sumFits : d.val[0]!.val + (5#u64).val ≤ UScalar.max .U64 := by
    simp only [base, UScalar.max_UScalarTy_U64_eq, U64.max_eq, show (5#u64).val = 5 by decide] at f0 ⊢
    omega
  step with (UScalar.add_spec sumFits) as ⟨col0, w0⟩
  step with (source_carry_pair_refines col0 d.val[1]! (by simp only [base] at f0 f1 ⊢; omega))
    as ⟨r0, col1, lo0, w1⟩
  step with (source_carry_pair_refines col1 d.val[2]! (by simp only [base] at *; omega))
    as ⟨r1, col2, lo1, w2⟩
  step with (source_carry_pair_refines col2 d.val[3]! (by simp only [base] at *; omega))
    as ⟨r2, col3, lo2, w3⟩
  step with (source_carry_pair_refines col3 d.val[4]! (by simp only [base] at *; omega))
    as ⟨r3, col4, lo3, w4⟩
  simp only [RADIX_BITS, shift26, limb_mask_exact, lift, Aeneas.Std.bind_tc_ok]
  let top : U64 := ⟨col4.bv.ushiftRight 26⟩
  have topEq : top.val = col4.val / base := shift26_value col4
  let r4 := col4 &&& 67108863#u64
  let reduced := Aeneas.Std.Array.make 5#usize [r0, r1, r2, r3, r4]
  have reducedEq : columns reduced = ⟨col0.val % base, col1.val % base, col2.val % base,
      col3.val % base, col4.val % base⟩ := by
    simp only [reduced, r4, columns, lo0, lo1, lo2, lo3, low_bits, Aeneas.Std.Array.make_val,
      List.getElem!_cons_zero, List.getElem!_cons_succ]
  have reducedBound : bounded (columns reduced) base := by
    rw [reducedEq]
    exact ⟨Nat.mod_lt _ (by decide), Nat.mod_lt _ (by decide), Nat.mod_lt _ (by decide),
      Nat.mod_lt _ (by decide), Nat.mod_lt _ (by decide)⟩
  have reducedValue := Abc.Spec.Poly1305.Go.normalized_value_bounded _ reducedBound
  have decomposition : value (columns d) + 5 = value (columns reduced) + base^5 * top.val := by
    rw [reducedEq, topEq]
    simp only [value, columns, base, show (5#u64).val = 5 by decide] at *
    omega
  have range : top.val ≤ 1 := by simp only [base] at decomposition inputValue; omega
  have canonical : Abc.Spec.Poly1305.Go.subtractIfNeeded (value (columns d)) = value (columns d) % modulus :=
    Abc.Spec.Poly1305.Go.canonical_residue _ inputValue
  by_cases overflow : top.val = 0
  · have zero : top = 0#u64 := UScalar.eq_of_val_eq overflow
    change (do
      let a ← select_reduced d.val[0]! r0 (core.num.U64.wrapping_sub 0#u64 top)
      let b ← select_reduced d.val[1]! r1 (core.num.U64.wrapping_sub 0#u64 top)
      let c ← select_reduced d.val[2]! r2 (core.num.U64.wrapping_sub 0#u64 top)
      let e ← select_reduced d.val[3]! r3 (core.num.U64.wrapping_sub 0#u64 top)
      let f ← select_reduced d.val[4]! r4 (core.num.U64.wrapping_sub 0#u64 top)
      .ok (Aeneas.Std.Array.make 5#usize [a,b,c,e,f])) ⦃ out => _ ⦄
    have noSubtract : ¬ base^5 ≤ value (columns d) + 5 := by rw [overflow] at decomposition; omega
    have originalVal : value (columns d) = value (columns d) % modulus := by
      rwa [Abc.Spec.Poly1305.Go.subtractIfNeeded, if_neg noSubtract] at canonical
    simp only [zero, show core.num.U64.wrapping_sub 0#u64 0#u64 = 0#u64 by rfl,
      wrapping_select_zero, Aeneas.Std.bind_tc_ok, WP.spec_ok, columns, Aeneas.Std.Array.make_val,
      List.getElem!_cons_zero, List.getElem!_cons_succ]
    exact ⟨fit, originalVal⟩
  · have topOne : top.val = 1 := by omega
    have one : top = 1#u64 := UScalar.eq_of_val_eq topOne
    have doSubtract : base^5 ≤ value (columns d) + 5 := by rw [topOne] at decomposition; omega
    have reducedVal : value (columns reduced) = value (columns d) % modulus := by
      rw [← canonical, Abc.Spec.Poly1305.Go.subtractIfNeeded, if_pos doSubtract]
      rw [topOne] at decomposition
      omega
    have exactMask : core.num.U64.wrapping_sub 0#u64 top = 18446744073709551615#u64 := by rw [one]; rfl
    simp only [show core.num.U64.wrapping_sub 0#u64 (⟨col4.bv.ushiftRight 26⟩ : U64) =
        18446744073709551615#u64 from exactMask, wrapping_select_ones, Aeneas.Std.bind_tc_ok, WP.spec_ok]
    exact ⟨reducedBound, reducedVal⟩

private theorem shift_left_128 (word : U128) (count : U32) (fits : count.val < 128) :
    (word <<< count) = .ok (⟨word.bv <<< count.val⟩ : U128) := by
  change (if count.val < 128 then Result.ok (⟨word.bv <<< count.val⟩ : U128)
    else Result.fail .integerOverflow) = _
  rw [if_pos fits]

private theorem shift_left_128_val (word : U128) (count : Nat) :
    (⟨word.bv <<< count⟩ : U128).val = (2^count * word.val) % 2^128 := by
  change (word.bv <<< count).toNat = _
  rw [BitVec.toNat_shiftLeft, Nat.shiftLeft_eq]
  exact congrArg (fun n => n % 2^128) (Nat.mul_comm word.bv.toNat (2^count))

private theorem wide_cast (word : U64) : (UScalar.cast .U128 word).val = word.val := by
  rw [UScalar.cast_val_eq]
  exact Nat.mod_eq_of_lt (by scalar_tac)

private theorem or128_val (low high : U128) : (low ||| high).val = low.val ||| high.val :=
  BitVec.toNat_or _ _

private theorem or_radix_digit {low digit bits : Nat} (fits : low < 2^bits) :
    low ||| (2^bits * digit) = low + 2^bits * digit := by
  rw [Nat.or_comm, Nat.add_comm]
  exact (Nat.two_pow_add_eq_or_of_lt fits digit).symm

/-- Packing normalized limbs keeps exactly the low 128 bits, including
truncation of the upper two bits of the final limb. -/
theorem source_pack_low128_refines (d : Words) (fit : bounded (columns d) base) :
    pack_low128 d ⦃ out => out.val = value (columns d) % 2^128 ⦄ := by
  simp only [bounded, columns, base] at fit
  rcases fit with ⟨f0, f1, f2, f3, f4⟩
  have times2 : (2#u32 * 26#u32 : Result U32) = .ok 52#u32 := by rfl
  have times3 : (3#u32 * 26#u32 : Result U32) = .ok 78#u32 := by rfl
  have times4 : (4#u32 * 26#u32 : Result U32) = .ok 104#u32 := by rfl
  simp (disch := decide) only [pack_low128, index0, index1, index2, index3, index4, RADIX_BITS,
    times2, times3, times4, lift, Aeneas.Std.bind_tc_ok, WP.spec_ok, or128_val, wide_cast,
    shift_left_128, shift_left_128_val, show (26#u32).val = 26 by decide,
    show (52#u32).val = 52 by decide, show (78#u32).val = 78 by decide,
    show (104#u32).val = 104 by decide]
  have s1 : 2^26 * d.val[1]!.val < 2^128 := by omega
  have s2 : 2^52 * d.val[2]!.val < 2^128 := by omega
  have s3 : 2^78 * d.val[3]!.val < 2^128 := by omega
  have top : (2^104 * d.val[4]!.val) % 2^128 = 2^104 * (d.val[4]!.val % 2^24) := by
    rw [show 2^128 = 2^104 * 2^24 by decide, Nat.mul_mod_mul_left]
  have l2 : d.val[0]!.val + 2^26 * d.val[1]!.val < 2^52 := by omega
  have l3 : d.val[0]!.val + 2^26 * d.val[1]!.val + 2^52 * d.val[2]!.val < 2^78 := by omega
  have l4 : d.val[0]!.val + 2^26 * d.val[1]!.val + 2^52 * d.val[2]!.val +
      2^78 * d.val[3]!.val < 2^104 := by omega
  rw [Nat.mod_eq_of_lt s1, Nat.mod_eq_of_lt s2, Nat.mod_eq_of_lt s3, top,
    or_radix_digit f0, or_radix_digit l2, or_radix_digit l3, or_radix_digit l4]
  simp only [value, columns, base]
  omega

/-- Adding decoded message limbs, folded multiplication and carry form the
exact unbounded recurrence on every admitted accumulator, key and block. -/
theorem source_absorb_limbs_refines (h r : Words) (rFive : Multiples) (message : Words)
    (state : live (columns h)) (key : bounded (columns r) base)
    (block : bounded (columns message) base) (cache : cachedMultiples r rFive) :
    absorb_limbs h r rFive message
      ⦃ out => columns out = Abc.Spec.Poly1305.Go.absorb (columns r) (columns h) (columns message) ⦄ := by
  have sums := added_block_fits (columns h) (columns message) state block
  simp only [addColumns, bounded, columns, base] at sums
  rcases sums with ⟨s0, s1, s2, s3, s4⟩
  simp (disch := decide) only [absorb_limbs, index0, index1, index2, index3, index4, Aeneas.Std.bind_tc_ok]
  simp (disch := omega) only [add_word, Aeneas.Std.bind_tc_ok]
  let added := Aeneas.Std.Array.make 5#usize
      [natWord (h.val[0]!.val + message.val[0]!.val),
        natWord (h.val[1]!.val + message.val[1]!.val),
        natWord (h.val[2]!.val + message.val[2]!.val),
        natWord (h.val[3]!.val + message.val[3]!.val),
        natWord (h.val[4]!.val + message.val[4]!.val)]
  have addedEq : columns added = addColumns (columns h) (columns message) := by
    simp (disch := omega) only [added, columns, addColumns, Aeneas.Std.Array.make_val,
      List.getElem!_cons_zero, List.getElem!_cons_succ, natWord_val]
  have addedBound : bounded (columns added) (3 * base) := by
    rw [addedEq]
    exact added_block_fits _ _ state block
  step with (source_multiply_refines added r rFive addedBound key cache) as ⟨multiplied, colEq⟩
  have colBound : bounded (columns multiplied) (2^59) := by
    rw [colEq]
    exact product_columns_fit _ _ addedBound key
  step with (source_carry_refines multiplied colBound) as ⟨out, outEq⟩
  rw [outEq, colEq, addedEq]
  rfl

/-- The exact Rust limb transition preserves the reachable state invariant
and advances the RFC polynomial recurrence modulo 2^130 minus five. -/
theorem source_absorb_polynomial_step (h r : Words) (rFive : Multiples) (message : Words)
    (state : live (columns h)) (key : bounded (columns r) base)
    (block : bounded (columns message) base) (cache : cachedMultiples r rFive) :
    absorb_limbs h r rFive message
      ⦃ out => live (columns out) ∧ value (columns out) % modulus =
        polynomialStep (value (columns r)) (value (columns h) % modulus) (columns message) ⦄ := by
  refine WP.spec_mono (source_absorb_limbs_refines h r rFive message state key block cache) ?_
  intro out matching
  rw [matching]
  exact ⟨absorb_fits _ _ _ key state block, absorb_value _ _ _⟩

#print axioms source_carry_pair_refines
#print axioms source_carry_upper_refines
#print axioms source_carry_refines
#print axioms source_final_carry_refines
#print axioms source_reduce_final_refines
#print axioms source_pack_low128_refines
#print axioms source_key_multiples_refines
#print axioms source_multiply_refines
#print axioms source_absorb_limbs_refines
#print axioms source_absorb_polynomial_step

end Abc.Refine.Poly1305
