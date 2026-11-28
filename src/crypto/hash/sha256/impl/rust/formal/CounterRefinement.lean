import Abc.Sha256.Extracted.Funs
import StreamingRefinement

namespace Abc.Refine.Sha256.Implementation

open Aeneas Aeneas.Std

private theorem usize_fits_u64 (length : Usize) : length.val < 2 ^ 64 := by
  have width : UScalarTy.Usize.numBits ≤ 64 := by
    rcases System.Platform.numBits_eq with width32 | width64
    · simp [UScalarTy.numBits, width32]
    · simp [UScalarTy.numBits, width64]
  exact Nat.lt_of_lt_of_le length.hBounds (Nat.pow_le_pow_right (by decide) width)

private theorem cast_usize_to_u64 (length : Usize) :
    (UScalar.cast .U64 length).val = length.val :=
  UScalar.cast_val_mod_pow_of_inBounds_eq .U64 length (usize_fits_u64 length)

/-- Both pointer widths supported by the Aeneas model fit into the counter. -/
theorem update_cast_roundtrip (input : Slice U8) :
    UScalar.cast .Usize (UScalar.cast .U64 (Slice.len input)) = Slice.len input := by
  apply UScalar.eq_of_val_eq
  rw [UScalar.cast_val_eq, cast_usize_to_u64]
  exact Nat.mod_eq_of_lt (Slice.len input).hBounds

theorem update_cast_length (input : Slice U8) :
    (UScalar.cast .U64 (Slice.len input)).val = input.val.length := by
  rw [cast_usize_to_u64, Slice.len_val]

theorem update_maximum_eq :
    Abc.Sha256.Extracted.MAX_MESSAGE_BYTES = .ok 2305843009213693951#u64 := by
  unfold Abc.Sha256.Extracted.MAX_MESSAGE_BYTES
  rfl

theorem update_maximum :
    Abc.Sha256.Extracted.MAX_MESSAGE_BYTES ⦃ n => n.val = Streaming.counterMaximum ⦄ := by
  rw [update_maximum_eq, WP.spec_ok]
  rfl

end Abc.Refine.Sha256.Implementation
