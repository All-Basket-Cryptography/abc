import Abc.Poly1305.Extracted.Funs

namespace Abc.Refine.Poly1305.Encoding

open Aeneas Aeneas.Std
open Aeneas.Std.Result
open Abc.Poly1305.Extracted

private theorem extracted_mask : LIMB_MASK = .ok 67108863#u64 := by
  have shifted : (1#u64 <<< 26#u32) = .ok 67108864#u64 := by rfl
  rw [LIMB_MASK, RADIX_BITS, shifted, Aeneas.Std.bind_tc_ok]
  have ordered : (1#u64).val ≤ (67108864#u64).val := by decide
  obtain ⟨word, result, exactValue⟩ := WP.spec_imp_exists (UScalar.sub_spec ordered)
  rw [result]
  rw [show word = 67108863#u64 from UScalar.eq_of_val_eq (by simpa using exactValue)]

private theorem shift_ok (value : U128) (count : U32) (bound : count.val < 128) :
    (value >>> count) = .ok (⟨value.bv.ushiftRight count.val⟩ : U128) := by
  change (if count.val < 128 then Result.ok (⟨value.bv.ushiftRight count.val⟩ : U128)
    else Result.fail .integerOverflow) = _
  rw [if_pos bound]

private theorem shifted_value (value : U128) (count : Nat) :
    (⟨value.bv.ushiftRight count⟩ : U128).val = value.val / 2^count := by
  change (value.bv >>> count).toNat = value.val / 2^count
  rw [BitVec.toNat_ushiftRight, Nat.shiftRight_eq_div_pow]
  rfl

private theorem cast_and_mask (value : U128) :
    (UScalar.cast .U64 value &&& 67108863#u64).val = value.val % 2^26 := by
  change ((UScalar.cast .U64 value).bv &&& 67108863#64).toNat = _
  rw [BitVec.toNat_and]
  change (UScalar.cast .U64 value).val &&& (2^26 - 1) = _
  rw [Nat.and_two_pow_sub_one_eq_mod, UScalar.cast_val_eq]
  change value.val % 2^64 % 2^26 = value.val % 2^26
  exact Nat.mod_mod_of_dvd _ (by decide)

theorem source_limbs_refines (value : U128) :
    limbs value ⦃ out => out.val.map (fun word => word.val) =
      (List.range 5).map (fun i => (value.val / 2^(26*i)) % 2^26) ⦄ := by
  have times2 : (2#u32 * 26#u32 : Result U32) = .ok 52#u32 := by rfl
  have times3 : (3#u32 * 26#u32 : Result U32) = .ok 78#u32 := by rfl
  have times4 : (4#u32 * 26#u32 : Result U32) = .ok 104#u32 := by rfl
  simp (disch := decide) only [limbs, RADIX_BITS, extracted_mask, times2, times3, times4,
    shift_ok, lift, Aeneas.Std.bind_tc_ok, WP.spec_ok, Aeneas.Std.Array.make_val,
    List.map_cons, List.map_nil, cast_and_mask, shifted_value]
  rw [show List.range 5 = [0, 1, 2, 3, 4] by decide]
  simp only [List.map_cons, List.map_nil, Nat.mul_zero, Nat.pow_zero, Nat.div_one, Nat.mul_one,
    show (26#u32).val = 26 by decide, show (52#u32).val = 52 by decide,
    show (78#u32).val = 78 by decide, show (104#u32).val = 104 by decide,
    show 26*2 = 52 by decide, show 26*3 = 78 by decide, show 26*4 = 104 by decide]

#print axioms source_limbs_refines

end Abc.Refine.Poly1305.Encoding
