import Abc.HkdfSha256.Extracted.Funs
import CounterRefinement
import HkdfLengthRefinement

namespace Abc.Refine.HkdfSha256

open Aeneas Aeneas.Std
open Abc.Spec.Sha256 (Message)
open Abc.Spec.HkdfSha256
open Abc.HkdfSha256.Extracted

def rustError : Abc.Spec.HkdfSha256.Error → HkdfError
  | .saltTooLong => .SaltTooLong
  | .inputTooLong => .InputTooLong
  | .prkTooShort => .PrkTooShort
  | .prkTooLong => .PrkTooLong
  | .infoTooLong => .InfoTooLong
  | .outputTooLong => .OutputTooLong

def validationResult :
    Except Abc.Spec.HkdfSha256.Error Unit → core.result.Result Unit HkdfError
  | .ok () => .Ok ()
  | .error reason => .Err (rustError reason)

private theorem tag_bytes_eq : abc_hmac_sha256.TAG_BYTES = .ok 32#usize := by
  unfold abc_hmac_sha256.TAG_BYTES Abc.HmacSha256.Extracted.TAG_BYTES
    abc_sha256.DIGEST_BYTES Abc.Sha256.Extracted.DIGEST_BYTES
  rfl

private theorem prk_bytes_eq : PRK_BYTES = .ok 32#usize := by
  unfold PRK_BYTES
  exact tag_bytes_eq

private theorem key_limit_eq : abc_hmac_sha256.MAX_KEY_BYTES = .ok 2305843009213693951#u64 := by
  unfold abc_hmac_sha256.MAX_KEY_BYTES Abc.HmacSha256.Extracted.MAX_KEY_BYTES
  exact Abc.Refine.Sha256.Implementation.update_maximum_eq

private theorem input_limit_eq : abc_hmac_sha256.MAX_INPUT_BYTES = .ok 2305843009213693887#u64 := by
  unfold abc_hmac_sha256.MAX_INPUT_BYTES Abc.HmacSha256.Extracted.MAX_INPUT_BYTES
  have block : UScalar.cast .U64 Abc.HmacSha256.Extracted.BLOCK_BYTES = 64#u64 := by
    unfold Abc.HmacSha256.Extracted.BLOCK_BYTES
    apply UScalar.eq_of_val_eq
    simp
  simp only [Abc.Refine.Sha256.Implementation.update_maximum_eq, lift, bind_tc_ok, block]
  rfl

private theorem output_limit_eq : MAX_OUTPUT_BYTES = .ok 8160#usize := by
  have cast : UScalar.cast .Usize core.num.U8.MAX = 255#usize := by
    apply UScalar.eq_of_val_eq
    rw [UScalar.cast_val_eq]
    change 255 % 2 ^ UScalarTy.Usize.numBits = (255#usize).val
    rw [Nat.mod_eq_of_lt]
    · simp
    · rcases System.Platform.numBits_eq with width32 | width64
      · simp [UScalarTy.numBits, width32]
      · simp [UScalarTy.numBits, width64]
  unfold MAX_OUTPUT_BYTES
  simp only [lift, tag_bytes_eq, bind_tc_ok, cast]
  obtain ⟨value, ran, product⟩ := WP.spec_imp_exists
    (@Usize.mul_spec 255#usize 32#usize (by scalar_tac))
  have exactValue : value = 8160#usize := UScalar.eq_of_val_eq (by scalar_tac)
  rw [ran, exactValue]

/-- All scalar guards are evaluated before the expansion loop. -/
theorem validate_expansion_refines (prk info output : Usize) :
    validate_expansion prk info output =
      .ok (validationResult (validateExpansion prk.val info.val output.val)) := by
  unfold validate_expansion validateExpansion
  simp only [prk_bytes_eq, key_limit_eq, tag_bytes_eq, input_limit_eq, output_limit_eq, lift, bind_tc_ok,
    usize_u64_roundtrip, bne_self_eq_false, Bool.false_eq_true, if_false, UScalar.lt_equiv,
    usize_as_u64, tagBytes, maximumOutput]
  by_cases short : prk.val < 32
  · simp [short, validationResult, rustError]
  by_cases keyLong : 2305843009213693951 < prk.val
  · have invalidKey := (key_above_limit _).mp keyLong
    simp [short, keyLong, invalidKey, validationResult, rustError]
  have allowedKey : Abc.Spec.Sha256.byteLengthAllowed prk.val := by
    by_contra! invalid
    exact keyLong ((key_above_limit _).mpr invalid)
  by_cases outputLong : 8160 < output.val
  · simp [short, keyLong, allowedKey, outputLong, validationResult, rustError]
  by_cases empty : output.val = 0
  · have zero : output = 0#usize := UScalar.eq_of_val_eq (by simpa using empty)
    simp [short, keyLong, allowedKey, zero, validationResult]
  have nonzero : output ≠ 0#usize := by
    intro equal
    exact empty (by simp [equal])
  simp only [short, if_false, allowedKey, decide_true, Bool.not_true, outputLong, nonzero, empty]
  have limit := info_above_limit info.val output.val
  by_cases large : 32 < output.val
  · simp only [infoOverhead, tagBytes, if_pos large] at limit
    have castTag : UScalar.cast .U64 (32#usize) = 32#u64 := UScalar.eq_of_val_eq (by simp)
    have add : (32#u64 + 1#u64 : Result U64) = .ok 33#u64 := rfl
    have subtract : (2305843009213693887#u64 - 33#u64 : Result U64) = .ok 2305843009213693854#u64 := rfl
    by_cases fits : infoAllowed info.val output.val <;>
      simp [short, keyLong, outputLong, large, castTag, add, subtract, limit, fits, validationResult, rustError]
  · simp only [infoOverhead, tagBytes, if_neg large] at limit
    have subtract : (2305843009213693887#u64 - 1#u64 : Result U64) = .ok 2305843009213693886#u64 := rfl
    by_cases fits : infoAllowed info.val output.val <;>
      simp [short, keyLong, outputLong, large, subtract, limit, fits, validationResult, rustError]

end Abc.Refine.HkdfSha256
