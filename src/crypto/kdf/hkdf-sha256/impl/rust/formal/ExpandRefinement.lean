import Abc.HkdfSha256.Extracted.Funs
import ExpandBlockRefinement
import ExpandInvariant
import ModelView

open Aeneas Aeneas.Std
open Aeneas.Std.Result Aeneas.Std.ControlFlow

namespace Abc.Refine.HkdfSha256.Implementation

open Abc.Spec.Sha256 (Message)
open Abc.Spec.HkdfSha256
open Abc.Refine.Sha256.Implementation (bytesView bytesView_append bytesView_length bytesView_take)

set_option maxHeartbeats 1500000

private abbrev Block := Aeneas.Std.Array U8 32#usize

private theorem tag_bytes_eq : abc_hmac_sha256.TAG_BYTES = .ok 32#usize := by
  change Abc.HmacSha256.Extracted.TAG_BYTES = _
  unfold Abc.HmacSha256.Extracted.TAG_BYTES
  change Result.ok Abc.Sha256.Extracted.DIGEST_BYTES = _
  rw [Abc.Sha256.Extracted.DIGEST_BYTES]

/-- The copied tag prefix fits the output and leaves all earlier bytes in order. -/
theorem copy_block_refines (output : Slice U8) (start : Usize) (tag : Block)
    (startBound : start.val ≤ output.val.length) (outputBound : output.val.length ≤ maximumOutput) :
    Abc.HkdfSha256.Extracted.copy_block output start tag
      ⦃ result => result.1.val = min (start.val + tagBytes) output.val.length ∧
        result.2.val.length = output.val.length ∧
        result.2.val.take result.1.val = output.val.take start.val ++ tag.val.take (result.1.val - start.val) ⦄ := by
  have smallOutput : output.val.length ≤ 8160 := outputBound
  unfold Abc.HkdfSha256.Extracted.copy_block Abc.HkdfSha256.Extracted.copy_block_loop
  refine loop.spec_decr_nat
    (fun triple : Slice U8 × Usize × Usize => tagBytes - triple.2.2.val)
    (fun triple => triple.1.val.length = output.val.length ∧ triple.2.2.val ≤ tagBytes ∧
      triple.2.1.val ≤ output.val.length ∧ triple.2.1.val = start.val + triple.2.2.val ∧
      triple.1.val.take triple.2.1.val = output.val.take start.val ++ tag.val.take triple.2.2.val)
    _ _ _ ?_ ?_
  · rintro ⟨written, offset, i⟩ ⟨sizeEq, copiedBound, inside, position, content⟩
    dsimp only at sizeEq copiedBound inside position content
    unfold Abc.HkdfSha256.Extracted.copy_block_loop.body
    simp only [tag_bytes_eq, bind_tc_ok]
    split
    next stillTag =>
      have bytesLeft : i.val < tagBytes := by simpa [tagBytes] using stillTag
      split
      next stillOutput =>
        have writable : offset.val < written.val.length := by scalar_tac
        have readable : i.val < tag.val.length := by simpa [tagBytes] using bytesLeft
        step as ⟨byte, byteEq⟩
        step as ⟨updated, updatedEq⟩
        step as ⟨nextI, nextIEq⟩
        step as ⟨nextOffset, nextOffsetEq⟩
        have indexNat : nextI.val = i.val + 1 := by scalar_tac
        have offsetNat : nextOffset.val = offset.val + 1 := by scalar_tac
        refine ⟨?_, by omega, by omega, by omega, ?_, by omega⟩
        · simp [updatedEq, Slice.set_val_eq, sizeEq]
        · rw [updatedEq, Slice.set_val_eq, offsetNat, take_after_set _ _ _ writable, content, indexNat,
            byteEq, List.take_succ_eq_append_getElem readable, List.append_assoc]
      next filled =>
        have noRoom : ¬ offset.val < output.val.length := by simpa [sizeEq] using filled
        have done : offset.val = output.val.length := by omega
        have picked : min (start.val + tagBytes) output.val.length = output.val.length := by
          apply Nat.min_eq_right
          omega
        simp only [WP.spec_ok]
        exact ⟨done.trans picked.symm, sizeEq, by simpa [show offset.val - start.val = i.val by omega] using content⟩
    next exhaustedTag =>
      have noBytes : ¬ i.val < tagBytes := by simpa [tagBytes] using exhaustedTag
      have done : i.val = tagBytes := by omega
      have picked : min (start.val + tagBytes) output.val.length = start.val + tagBytes := by
        apply Nat.min_eq_left
        omega
      simp only [WP.spec_ok]
      exact ⟨by omega, sizeEq, by simpa [show offset.val - start.val = i.val by omega] using content⟩
  · simp [startBound]

/-- Each exact Rust iteration appends the next RFC tag, truncated only at the caller's output boundary. -/
theorem expand_loop_refines (prk info output : Slice U8) (initial : Block)
    (valid : ValidExpansion prk.val.length info.val.length output.val.length) :
    Abc.HkdfSha256.Extracted.expand_loop prk info output initial 0#usize 1#usize
      ⦃ result => result.1 = core.result.Result.Ok () ∧
        bytesView result.2.val = expandMaterial (bytesView prk.val) (bytesView info.val) output.val.length ⦄ := by
  let length := output.val.length
  let key := bytesView prk.val
  let context := bytesView info.val
  have specValid : ValidExpansion key.length context.length length := by
    simpa [key, context, length] using valid
  unfold Abc.HkdfSha256.Extracted.expand_loop
  refine loop.spec_decr_nat
    (fun tuple : Slice U8 × Block × Usize × Usize => length - tuple.2.2.1.val)
    (fun tuple => ∃ count : Nat,
      tuple.1.val.length = length ∧ count ≤ blockCount length ∧ tuple.2.2.2.val = count + 1 ∧
      tuple.2.2.1.val = min (tagBytes * count) length ∧
      (0 < count → bytesView tuple.2.1.val = block key context count) ∧
      bytesView (tuple.1.val.take tuple.2.2.1.val) = (material key context count).take tuple.2.2.1.val)
    _ _ _ ?_ ?_
  · rintro ⟨written, previous, offset, counter⟩ ⟨count, sizeEq, countBound, counterEq, position, lastTag, content⟩
    dsimp only at sizeEq countBound counterEq position lastTag content
    unfold Abc.HkdfSha256.Extracted.expand_loop.body
    dsimp only
    split
    next guard =>
      have remaining : offset.val < length := by simpa [sizeEq, Slice.length] using guard
      have nextBound : count + 1 ≤ blockCount length := remaining_block position remaining
      have maxCount := blockCount_le_255 length valid.outputMaximum
      have maxCounter : counter.val ≤ 255 := by omega
      have castCounter : (UScalar.cast .U8 counter).val = count + 1 := by
        rw [UScalar.cast_val_eq, Nat.mod_eq_of_lt]
        · exact counterEq
        · change counter.val < 256
          omega
      simp only [lift, bind_tc_ok]
      have resultSpec := expand_block_refines prk info previous (UScalar.cast .U8 counter) length count valid
        nextBound castCounter lastTag
      obtain ⟨result, evaluated, tag, rfl, tagEq⟩ := (WP.spec_equiv_exists _ _).mp resultSpec
      rw [evaluated]
      simp only [bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
      have startBound : offset.val ≤ written.val.length := by omega
      have outputBound : written.val.length ≤ maximumOutput := by simpa [sizeEq] using valid.outputMaximum
      step with (copy_block_refines written offset tag startBound outputBound)
        as ⟨next, updated, nextEq, updatedSize, updatedContent⟩
      step as ⟨nextCounter, nextCounterEq⟩
      have counterNat : nextCounter.val = counter.val + 1 := by scalar_tac
      have positionNext : next.val = min (tagBytes * (count + 1)) length := by
        rw [nextEq, sizeEq, next_offset position remaining]
      have grows : offset.val < next.val := by
        rw [nextEq, sizeEq]
        simp only [tagBytes]
        omega
      have priorFull : (material key context count).length = offset.val := by
        rw [material_length key context length count specValid countBound, remaining_offset position remaining]
      refine ⟨?_, by omega⟩
      refine ⟨count + 1, updatedSize.trans sizeEq, nextBound, by omega, positionNext, fun _ => tagEq, ?_⟩
      rw [updatedContent, bytesView_append]
      simp only [bytesView_take] at content ⊢
      rw [tagEq, content,
        take_material_succ key context count offset.val next.val priorFull (by omega)]
    next guard =>
      have stopped : length ≤ offset.val := by
        have closed : ¬ offset.val < length := by simpa [sizeEq, Slice.length] using guard
        omega
      have countEq := completed_blocks position stopped countBound
      have offsetEq : offset.val = length := by omega
      have whole : written.val.take offset.val = written.val := by
        apply List.take_of_length_le
        omega
      rw [whole, offsetEq, countEq] at content
      simp only [WP.spec_ok]
      exact ⟨True.intro, by simpa [expandMaterial] using content⟩
  · exact ⟨0, rfl, Nat.zero_le _, by simp, by simp, by omega, by simp [material, bytesView]⟩

end Abc.Refine.HkdfSha256.Implementation
