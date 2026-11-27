import Aeneas
import HkdfSpec

namespace Abc.Refine.HkdfSha256

open Aeneas Aeneas.Std
open Abc.Spec.HkdfSha256

theorem usize_as_u64 (length : Usize) : (UScalar.cast .U64 length).val = length.val := by
  have width : UScalarTy.Usize.numBits ≤ 64 := by
    rcases System.Platform.numBits_eq with width32 | width64
    · simp [UScalarTy.numBits, width32]
    · simp [UScalarTy.numBits, width64]
  apply UScalar.cast_val_mod_pow_of_inBounds_eq
  exact Nat.lt_of_lt_of_le length.hBounds (Nat.pow_le_pow_right (by decide) width)

theorem usize_u64_roundtrip (length : Usize) :
    UScalar.cast .Usize (UScalar.cast .U64 length) = length := by
  apply UScalar.eq_of_val_eq
  rw [UScalar.cast_val_eq, usize_as_u64]
  exact Nat.mod_eq_of_lt length.hBounds

theorem key_above_limit (length : Nat) :
    2305843009213693951 < length ↔ ¬ Abc.Spec.Sha256.byteLengthAllowed length := by
  change 2305843009213693951 < length ↔ ¬ 8 * length < 18446744073709551616
  omega

theorem info_above_limit (infoLength outputLength : Nat) :
    2305843009213693887 - infoOverhead outputLength < infoLength ↔
      ¬ infoAllowed infoLength outputLength := by
  have overhead : infoOverhead outputLength ≤ 33 := by
    unfold infoOverhead tagBytes
    split <;> decide
  change _ ↔ ¬ 8 * (64 + infoLength + infoOverhead outputLength) < 18446744073709551616
  omega

end Abc.Refine.HkdfSha256
