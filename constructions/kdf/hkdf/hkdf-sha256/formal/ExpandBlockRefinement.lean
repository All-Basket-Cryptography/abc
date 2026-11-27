import Abc.HkdfSha256.Extracted.Funs
import HkdfSpec
import HmacRefinement

open Aeneas Aeneas.Std
open Aeneas.Std.Result

namespace Abc.Refine.HkdfSha256.Implementation

open Abc.Spec.Sha256 (Message byteLengthAllowed)
open Abc.Spec.HkdfSha256
open Abc.Refine.Sha256.Implementation (bytesView bytesView_length)

private abbrev Block := Aeneas.Std.Array U8 32#usize
private abbrev HmacState := Abc.HmacSha256.Extracted.HmacSha256
private abbrev Represents := Abc.Refine.HmacSha256.Implementation.Represents

private theorem accepted_hmac_update (state : HmacState) (keyBlock message : Message) (input : Slice U8)
    (stateRep : Represents state keyBlock message)
    (fits : Abc.Spec.HmacSha256.messageAllowed (message.length + (bytesView input.val).length)) :
    ∃ updated, abc_hmac_sha256.HmacSha256.update state input = .ok (.Ok (), updated) ∧
      Represents updated keyBlock (message ++ bytesView input.val) := by
  obtain ⟨⟨result, updated⟩, evaluated, correct⟩ := WP.spec_imp_exists
    (Abc.Refine.HmacSha256.Implementation.update_refines state keyBlock message input stateRep)
  simp only [if_pos fits] at correct
  obtain ⟨rfl, updatedRep⟩ := correct
  refine ⟨updated, ?_, updatedRep⟩
  simp [abc_hmac_sha256.HmacSha256.update, evaluated, abc_hmac_sha256.transportResult]

private def counterSlice (counter : U8) : Slice U8 := (Aeneas.Std.Array.make 1#usize [counter]).to_slice

private theorem counterSlice_view (counter : U8) : bytesView (counterSlice counter).val = [counter.bv] := by
  simp [counterSlice, bytesView]

/-- Both generated branches stream the context and counter to a prepared HMAC state. -/
private theorem finish_block_refines (state : HmacState) (key keyBlock prior : Message)
    (info : Slice U8) (counter : U8) (stateRep : Represents state keyBlock prior)
    (normalized : Abc.Spec.HmacSha256.normalizeKey key = some keyBlock)
    (keyFits : byteLengthAllowed key.length)
    (fits : Abc.Spec.HmacSha256.messageAllowed (prior ++ bytesView info.val ++ [counter.bv]).length) :
    (do
      let (updated, withInfo) ← abc_hmac_sha256.HmacSha256.update state info
      match updated with
      | .Ok _ =>
        let (updatedAgain, withCounter) ← abc_hmac_sha256.HmacSha256.update withInfo (counterSlice counter)
        match updatedAgain with
        | .Ok _ =>
          let finalized ← abc_hmac_sha256.HmacSha256.finalize withCounter
          match finalized with
          | .Ok tag => ok (core.result.Result.Ok tag)
          | .Err _ => ok (core.result.Result.Err Abc.HkdfSha256.Extracted.HkdfError.InfoTooLong)
        | .Err _ => ok (core.result.Result.Err Abc.HkdfSha256.Extracted.HkdfError.InfoTooLong)
      | .Err _ => ok (core.result.Result.Err Abc.HkdfSha256.Extracted.HkdfError.InfoTooLong))
      ⦃ result => ∃ tag, result = core.result.Result.Ok tag ∧
        bytesView tag.val = Abc.Spec.HmacSha256.tag key (prior ++ bytesView info.val ++ [counter.bv]) ⦄ := by
  have infoFits : Abc.Spec.HmacSha256.messageAllowed (prior.length + (bytesView info.val).length) := by
    simp only [List.length_append, List.length_singleton, Abc.Spec.HmacSha256.messageAllowed,
      byteLengthAllowed] at fits ⊢
    omega
  obtain ⟨withInfo, infoEvaluated, infoRep⟩ := accepted_hmac_update state keyBlock prior info stateRep infoFits
  have counterFits : Abc.Spec.HmacSha256.messageAllowed
      ((prior ++ bytesView info.val).length + (bytesView (counterSlice counter).val).length) := by
    simpa only [counterSlice_view, List.length_append] using fits
  obtain ⟨withCounter, counterEvaluated, finalRep⟩ :=
    accepted_hmac_update withInfo keyBlock (prior ++ bytesView info.val) (counterSlice counter) infoRep counterFits
  rw [counterSlice_view] at finalRep
  obtain ⟨tag, tagEvaluated, tagSpec⟩ := Abc.Refine.HmacSha256.Implementation.finalize_refines
    withCounter key keyBlock (prior ++ bytesView info.val ++ [counter.bv]) normalized finalRep
  rw [Abc.Spec.HmacSha256.authenticate_eq_ok keyFits fits] at tagSpec
  have correct := (Except.ok.inj tagSpec).symm
  simp [infoEvaluated, counterEvaluated, abc_hmac_sha256.HmacSha256.finalize, tagEvaluated,
    abc_hmac_sha256.transportResult, correct]

/-- The exact generated HMAC calls produce one RFC 5869 block. -/
theorem expand_block_refines (prk info : Slice U8) (previous : Block) (counter : U8) (length count : Nat)
    (valid : ValidExpansion prk.val.length info.val.length length)
    (within : count + 1 ≤ blockCount length) (counterEq : counter.val = count + 1)
    (lastTag : 0 < count → bytesView previous.val = block (bytesView prk.val) (bytesView info.val) count) :
    Abc.HkdfSha256.Extracted.expand_block prk previous info counter
      ⦃ result => ∃ tag, result = core.result.Result.Ok tag ∧
        bytesView tag.val = block (bytesView prk.val) (bytesView info.val) (count + 1) ⦄ := by
  let key := bytesView prk.val
  let context := bytesView info.val
  let prior := block key context count
  have specValid : ValidExpansion key.length context.length length := by simpa [key, context] using valid
  have counterByte : counter.bv = BitVec.ofNat 8 (count + 1) := by
    rw [← counterEq]
    exact (UScalar.Nat_cast_BitVec_val counter).symm
  have fits : Abc.Spec.HmacSha256.messageAllowed (prior ++ context ++ [counter.bv]).length := by
    rw [counterByte]
    exact block_message_allowed key context length count specValid within
  have expected : block key context (count + 1) = Abc.Spec.HmacSha256.tag key (prior ++ context ++ [counter.bv]) := by
    rw [counterByte, block]
  obtain ⟨state, keyBlock, created, normalized, emptyRep⟩ :=
    Abc.Refine.HmacSha256.Implementation.new_refines prk specValid.prkAllowed
  unfold Abc.HkdfSha256.Extracted.expand_block
  simp only [abc_hmac_sha256.HmacSha256.new, created, bind_tc_ok, abc_hmac_sha256.transportResult]
  change _ ⦃ result => ∃ tag : Block, result = core.result.Result.Ok tag ∧ bytesView tag.val = block key context (count + 1) ⦄
  rw [expected]
  by_cases later : 0 < count
  · have guard : 1#u8 < counter := by simp [counterEq]; omega
    rw [if_pos guard]
    have priorEq : bytesView previous.to_slice.val = prior := by
      simpa only [Aeneas.Std.Array.val_to_slice] using lastTag later
    have previousFits : Abc.Spec.HmacSha256.messageAllowed
        (([] : Message).length + (bytesView previous.to_slice.val).length) := by
      simp only [List.length_nil, Nat.zero_add, priorEq, Abc.Spec.HmacSha256.messageAllowed, byteLengthAllowed]
      simp only [List.length_append, List.length_singleton, Abc.Spec.HmacSha256.messageAllowed,
        byteLengthAllowed] at fits
      omega
    obtain ⟨withPrevious, evaluated, withPreviousRep⟩ :=
      accepted_hmac_update state keyBlock [] previous.to_slice emptyRep previousFits
    simp only [List.nil_append, priorEq] at withPreviousRep
    simp only [lift, bind_tc_ok, evaluated]
    exact finish_block_refines withPrevious key keyBlock prior info counter withPreviousRep normalized specValid.prkAllowed fits
  · have guard : ¬ 1#u8 < counter := by simp [counterEq]; omega
    rw [if_neg guard]
    have first : count = 0 := by omega
    have priorNil : prior = [] := by simp [prior, first, block]
    rw [priorNil] at fits ⊢
    simp only [lift, bind_tc_ok]
    exact finish_block_refines state key keyBlock [] info counter emptyRep normalized specValid.prkAllowed fits

end Abc.Refine.HkdfSha256.Implementation
