import HmacPadRefinement
import Refinement

namespace Abc.Refine.HmacSha256.Implementation

open Aeneas Aeneas.Std Result
open Abc.HmacSha256.Extracted (HmacSha256 HmacError)
open Abc.Refine.Sha256.Implementation (bytesView streamView)
open Abc.Spec.Sha256 (Message)
open Abc.Spec.HmacSha256 (innerPad outerPad zeroPad normalizeKey messageAllowed)

local notation "ShaModel" => Abc.Sha256.Extracted.Sha256
local notation "shaInitial" => Abc.Refine.Sha256.Implementation.initialModel
local notation "shaStream" => Abc.Refine.Sha256.Streaming.Represents Abc.Spec.Sha256.initial Abc.Spec.Sha256.compress

private theorem shaEmpty : shaStream (streamView shaInitial) [] := by
  rw [Abc.Refine.Sha256.Implementation.initial_streamView]
  exact Abc.Refine.Sha256.Streaming.initial_represents _ _

private theorem shaAccept (state : ShaModel) (message : Message) (input : Slice U8)
    (rep : shaStream (streamView state) message)
    (fits : Abc.Spec.Sha256.byteLengthAllowed (message.length + (bytesView input.val).length)) :
    ∃ next, Abc.Sha256.Extracted.Sha256.update state input = .ok (.Ok (), next) ∧
      shaStream (streamView next) (message ++ bytesView input.val) := by
  obtain ⟨⟨result, next⟩, updated, correct⟩ := WP.spec_imp_exists
    (Abc.Refine.Sha256.Implementation.update_refines state message input rep)
  simp only [if_pos fits] at correct
  exact ⟨next, correct.1 ▸ updated, correct.2⟩

private theorem shaDigestAccept (input : Slice U8)
    (fits : Abc.Spec.Sha256.byteLengthAllowed (bytesView input.val).length) :
    ∃ digest, Abc.Sha256.Extracted.digest input = .ok (.Ok digest) ∧
      Abc.Spec.Sha256.digest (bytesView input.val) = some (bytesView digest.val) := by
  obtain ⟨next, updated, rep⟩ := shaAccept shaInitial [] input shaEmpty (by simpa using fits)
  obtain ⟨digest, finalized, bytes⟩ := WP.spec_imp_exists
    (Abc.Refine.Sha256.Implementation.finalize_refines next _ rep)
  exact ⟨digest, Abc.Refine.Sha256.Implementation.digest_of_update_ok input next digest updated finalized,
    by simpa using bytes.symm⟩

private theorem shaDigestReject (input : Slice U8)
    (rejected : ¬ Abc.Spec.Sha256.byteLengthAllowed (bytesView input.val).length) :
    Abc.Sha256.Extracted.digest input = .ok (.Err ()) := by
  obtain ⟨result, updated, correct⟩ := WP.spec_imp_exists
    (Abc.Refine.Sha256.Implementation.update_refines shaInitial [] input shaEmpty)
  simp only [List.length_nil, Nat.zero_add, if_neg rejected] at correct
  exact Abc.Refine.Sha256.Implementation.digest_of_update_error input shaInitial (correct ▸ updated)

/-- Both SHA states represent the exact RFC 2104 prefixes. Only the inner state
    receives user updates before finalization. -/
structure Represents (state : HmacSha256) (keyBlock message : Message) : Prop where
  keyLength : keyBlock.length = 64
  inner : shaStream (streamView state.inner) (innerPad keyBlock ++ message)
  outer : shaStream (streamView state.outer) (outerPad keyBlock)

private def fromMaterial (material : Slice U8) : Result (core.result.Result HmacSha256 HmacError) := do
  let (inner, outer) ← Abc.HmacSha256.Extracted.xor_pads material
  let state ← abc_sha256.Sha256.new
  let (result, innerState) ← abc_sha256.Sha256.update state inner.to_slice
  match result with
  | .Ok _ =>
    let (result, outerState) ← abc_sha256.Sha256.update state outer.to_slice
    match result with
    | .Ok _ => .ok (.Ok ⟨innerState, outerState⟩)
    | .Err _ => .ok (.Err .MessageTooLong)
  | .Err _ => .ok (.Err .MessageTooLong)

private theorem fromMaterial_refines (material : Slice U8) (bounded : material.val.length ≤ 64) :
    ∃ state, fromMaterial material = .ok (.Ok state) ∧ Represents state (zeroPad (bytesView material.val)) [] := by
  obtain ⟨⟨inner, outer⟩, padded, innerEq, outerEq⟩ := WP.spec_imp_exists (xor_pads_refines material bounded)
  have keyLength : (zeroPad (bytesView material.val)).length = 64 := by
    simp [zeroPad]
    omega
  have padFits (pad : Aeneas.Std.Array U8 64#usize) :
      Abc.Spec.Sha256.byteLengthAllowed (([] : Message).length + (bytesView pad.to_slice.val).length) := by
    simp only [List.length_nil, Nat.zero_add, Aeneas.Std.Array.val_to_slice,
      Abc.Refine.Sha256.Implementation.bytesView_length, Aeneas.Std.Array.property]
    decide
  obtain ⟨innerState, updatedInner, innerStream⟩ := shaAccept shaInitial [] inner.to_slice shaEmpty (padFits inner)
  obtain ⟨outerState, updatedOuter, outerStream⟩ := shaAccept shaInitial [] outer.to_slice shaEmpty (padFits outer)
  refine ⟨⟨innerState, outerState⟩, ?_, keyLength, ?_, ?_⟩
  · simp [fromMaterial, padded, Abc.Refine.Sha256.Implementation.new_eq, updatedInner, updatedOuter]
  · simpa only [List.nil_append, List.append_nil, Aeneas.Std.Array.val_to_slice, innerEq] using innerStream
  · simpa only [List.nil_append, Aeneas.Std.Array.val_to_slice, outerEq] using outerStream

private theorem keyCondition (key : Slice U8) :
    Abc.HmacSha256.Extracted.BLOCK_BYTES < key.len ↔ 64 < key.val.length := by
  unfold Abc.HmacSha256.Extracted.BLOCK_BYTES
  constructor <;> intro condition <;> scalar_tac

/-- The constructor succeeds for every admissible key and initializes both hash streams. -/
theorem new_refines (key : Slice U8)
    (fits : Abc.Spec.Sha256.byteLengthAllowed (bytesView key.val).length) :
    ∃ state keyBlock, HmacSha256.new key = .ok (.Ok state) ∧
      normalizeKey (bytesView key.val) = some keyBlock ∧ Represents state keyBlock [] := by
  by_cases long : 64 < key.val.length
  · obtain ⟨digest, hashed, digestEq⟩ := shaDigestAccept key fits
    obtain ⟨state, initialized, rep⟩ := fromMaterial_refines digest.to_slice (by simp)
    have longBytes : ¬ (bytesView key.val).length ≤ 64 := by simpa using long
    refine ⟨state, zeroPad (bytesView digest.to_slice.val), ?_, ?_, rep⟩
    · unfold HmacSha256.new
      simp only [keyCondition, if_pos long, hashed, lift, bind_tc_ok]
      exact initialized
    · simp only [normalizeKey, if_neg longBytes, digestEq, Aeneas.Std.Array.val_to_slice]
      rfl
  · obtain ⟨state, initialized, rep⟩ := fromMaterial_refines key (by omega)
    have shortBytes : (bytesView key.val).length ≤ 64 := by simp; omega
    refine ⟨state, zeroPad (bytesView key.val), ?_, ?_, rep⟩
    · unfold HmacSha256.new
      simp only [keyCondition, if_neg long, lift, bind_tc_ok]
      exact initialized
    · simp only [normalizeKey, if_pos shortBytes]
      rfl

theorem new_rejects (key : Slice U8)
    (rejected : ¬ Abc.Spec.Sha256.byteLengthAllowed (bytesView key.val).length) :
    HmacSha256.new key = .ok (.Err .KeyTooLong) := by
  have long : 64 < key.val.length := by
    simp only [Abc.Refine.Sha256.Implementation.bytesView_length, Abc.Spec.Sha256.byteLengthAllowed] at rejected
    omega
  unfold HmacSha256.new
  simp only [keyCondition, if_pos long, shaDigestReject key rejected, bind_tc_ok]

/-- Appending a valid chunk extends the represented message. An over-limit
    update returns the exact prior Rust state and the public error variant. -/
theorem update_refines (state : HmacSha256) (keyBlock message : Message) (input : Slice U8)
    (rep : Represents state keyBlock message) :
    HmacSha256.update state input ⦃ out =>
      if messageAllowed (message.length + (bytesView input.val).length) then
        out.1 = .Ok () ∧ Represents out.2 keyBlock (message ++ bytesView input.val)
      else out = (.Err .MessageTooLong, state) ⦄ := by
  have domain : Abc.Spec.Sha256.byteLengthAllowed
      ((innerPad keyBlock ++ message).length + (bytesView input.val).length) ↔
      messageAllowed (message.length + (bytesView input.val).length) := by
    simp only [List.length_append, Abc.Spec.HmacSha256.innerPad_length, rep.keyLength, messageAllowed, Nat.add_assoc]
  obtain ⟨⟨result, next⟩, updated, correct⟩ := WP.spec_imp_exists
    (Abc.Refine.Sha256.Implementation.update_refines state.inner (innerPad keyBlock ++ message) input rep.inner)
  simp only [domain] at correct
  unfold HmacSha256.update
  by_cases allowed : messageAllowed (message.length + (bytesView input.val).length)
  · simp only [if_pos allowed] at correct ⊢
    obtain ⟨rfl, nextRep⟩ := correct
    simp only [updated, bind_tc_ok]
    exact ⟨rfl, rep.keyLength, by simpa only [List.append_assoc] using nextRep, rep.outer⟩
  · simp only [if_neg allowed] at correct ⊢
    cases correct
    simp only [updated, bind_tc_ok]
    cases state
    exact (WP.spec_ok _).mpr rfl

/-- Finalization succeeds and returns the full independent RFC 2104 tag. -/
theorem finalize_refines (state : HmacSha256) (key keyBlock message : Message)
    (normalized : normalizeKey key = some keyBlock) (rep : Represents state keyBlock message) :
    ∃ tag, HmacSha256.finalize state = .ok (.Ok tag) ∧
      Abc.Spec.HmacSha256.authenticate key message = .ok (bytesView tag.val) := by
  obtain ⟨innerDigest, innerFinalized, innerCorrect⟩ := WP.spec_imp_exists
    (Abc.Refine.Sha256.Implementation.finalize_refines state.inner _ rep.inner)
  have outerFits : Abc.Spec.Sha256.byteLengthAllowed
      ((outerPad keyBlock).length + (bytesView innerDigest.to_slice.val).length) := by
    simp only [Abc.Spec.HmacSha256.outerPad_length, rep.keyLength, Aeneas.Std.Array.val_to_slice,
      Abc.Refine.Sha256.Implementation.bytesView_length, Aeneas.Std.Array.property]
    decide
  obtain ⟨outerState, outerUpdated, outerRep⟩ := shaAccept state.outer _ innerDigest.to_slice rep.outer outerFits
  obtain ⟨tag, outerFinalized, outerCorrect⟩ := WP.spec_imp_exists
    (Abc.Refine.Sha256.Implementation.finalize_refines outerState _ outerRep)
  rw [Aeneas.Std.Array.val_to_slice] at outerCorrect
  refine ⟨tag, ?_, ?_⟩
  · simp [HmacSha256.finalize, lift, innerFinalized, outerUpdated, outerFinalized]
  · simp only [Abc.Spec.HmacSha256.authenticate, normalized, ← innerCorrect, ← outerCorrect]

def viewResult (result : core.result.Result (Aeneas.Std.Array U8 32#usize) HmacError) :
    Except Abc.Spec.HmacSha256.Error Message :=
  match result with
  | .Ok tag => .ok (bytesView tag.val)
  | .Err .KeyTooLong => .error .keyTooLong
  | .Err .MessageTooLong => .error .messageTooLong

/-- The exact generated one-shot entry point always returns the RFC tag or
    the corresponding public key/message error. -/
theorem authenticate_refines (key input : Slice U8) :
    Abc.HmacSha256.Extracted.authenticate key input ⦃ result =>
      viewResult result = Abc.Spec.HmacSha256.authenticate (bytesView key.val) (bytesView input.val) ⦄ := by
  by_cases keyFits : Abc.Spec.Sha256.byteLengthAllowed (bytesView key.val).length
  · obtain ⟨state, keyBlock, created, normalized, rep⟩ := new_refines key keyFits
    obtain ⟨⟨result, next⟩, updated, correct⟩ := WP.spec_imp_exists (update_refines state keyBlock [] input rep)
    simp only [List.length_nil, Nat.zero_add, List.nil_append] at correct
    by_cases inputFits : messageAllowed (bytesView input.val).length
    · simp only [if_pos inputFits] at correct
      obtain ⟨rfl, nextRep⟩ := correct
      obtain ⟨tag, finalized, tagCorrect⟩ := finalize_refines next _ keyBlock _ normalized nextRep
      rw [Abc.HmacSha256.Extracted.authenticate]
      simp [created, updated, finalized, core.result.Result.Insts.CoreOpsTry.branch, viewResult, tagCorrect]
    · simp only [if_neg inputFits] at correct
      cases correct
      rw [Abc.HmacSha256.Extracted.authenticate]
      simp [created, updated, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, viewResult, Abc.Spec.HmacSha256.authenticate_message_rejected keyFits inputFits]
  · rw [Abc.HmacSha256.Extracted.authenticate]
    simp [new_rejects key keyFits, core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, viewResult, Abc.Spec.HmacSha256.authenticate_key_rejected keyFits]

def appendAccepted (message input : Message) : Message :=
  if messageAllowed (message.length + input.length) then message ++ input else message

/-- Run the actual extracted updates, retaining the returned state after each call. -/
def updateAll (state : HmacSha256) (chunks : List (Slice U8)) : Result HmacSha256 :=
  match chunks with
  | [] => .ok state
  | input :: rest => do
    let (_, next) ← HmacSha256.update state input
    updateAll next rest

private theorem updateAll_refines (state : HmacSha256) (keyBlock message : Message)
    (chunks : List (Slice U8)) (rep : Represents state keyBlock message) :
    ∃ final, updateAll state chunks = .ok final ∧ Represents final keyBlock
      ((chunks.map (fun chunk => bytesView chunk.val)).foldl appendAccepted message) := by
  induction chunks generalizing state message with
  | nil => exact ⟨state, rfl, rep⟩
  | cons input rest ih =>
    obtain ⟨⟨result, next⟩, updated, correct⟩ := WP.spec_imp_exists (update_refines state keyBlock message input rep)
    have nextRep : Represents next keyBlock (appendAccepted message (bytesView input.val)) := by
      by_cases fits : messageAllowed (message.length + (bytesView input.val).length)
      · simp only [if_pos fits] at correct
        simpa only [appendAccepted, if_pos fits] using correct.2
      · simp only [if_neg fits] at correct
        cases correct
        simpa only [appendAccepted, if_neg fits] using rep
    obtain ⟨final, ran, finalRep⟩ := ih next _ nextRep
    exact ⟨final, by simp [updateAll, updated, ran], finalRep⟩

def finalizeTrace (key : Slice U8) (chunks : List (Slice U8)) :
    Result (core.result.Result (Aeneas.Std.Array U8 32#usize) HmacError) := do
  let result ← HmacSha256.new key
  match result with
  | .Err error => .ok (.Err error)
  | .Ok state =>
    let final ← updateAll state chunks
    HmacSha256.finalize final

/-- Every finite trace computes the tag of the accepted chunks in their original order. -/
theorem finalize_trace_refines (key : Slice U8) (chunks : List (Slice U8)) :
    finalizeTrace key chunks ⦃ result => viewResult result =
      Abc.Spec.HmacSha256.authenticate (bytesView key.val)
        ((chunks.map (fun chunk => bytesView chunk.val)).foldl appendAccepted []) ⦄ := by
  by_cases fits : Abc.Spec.Sha256.byteLengthAllowed (bytesView key.val).length
  · obtain ⟨state, keyBlock, created, normalized, rep⟩ := new_refines key fits
    obtain ⟨final, ran, finalRep⟩ := updateAll_refines state keyBlock [] chunks rep
    obtain ⟨tag, finalized, correct⟩ := finalize_refines final _ keyBlock _ normalized finalRep
    simp [finalizeTrace, created, ran, finalized, viewResult, correct]
  · simp [finalizeTrace, new_rejects key fits, viewResult, Abc.Spec.HmacSha256.authenticate_key_rejected fits]

private theorem appendAccepted_concat (message : Message) (chunks : List Message)
    (fits : messageAllowed (message.length + chunks.flatten.length)) :
    chunks.foldl appendAccepted message = message ++ chunks.flatten := by
  induction chunks generalizing message with
  | nil => simp
  | cons input rest ih =>
    have allFit : messageAllowed ((message ++ input).length + rest.flatten.length) := by
      simpa only [List.flatten_cons, List.length_append, Nat.add_assoc] using fits
    have firstFits : messageAllowed (message.length + input.length) := by
      unfold messageAllowed Abc.Spec.Sha256.byteLengthAllowed at allFit ⊢
      simp only [List.length_append] at allFit
      omega
    simp only [List.foldl_cons, appendAccepted, if_pos firstFits, ih _ allFit,
      List.flatten_cons, List.append_assoc]

/-- When every chunk fits, the trace equals authentication of their concatenation. -/
theorem finalize_trace_refines_concat (key : Slice U8) (chunks : List (Slice U8))
    (fits : messageAllowed (chunks.map (fun chunk => bytesView chunk.val)).flatten.length) :
    finalizeTrace key chunks ⦃ result => viewResult result =
      Abc.Spec.HmacSha256.authenticate (bytesView key.val)
        (chunks.map (fun chunk => bytesView chunk.val)).flatten ⦄ := by
  have concat := appendAccepted_concat [] (chunks.map (fun chunk => bytesView chunk.val))
    (by simpa only [List.length_nil, Nat.zero_add] using fits)
  simpa only [concat, List.nil_append] using finalize_trace_refines key chunks

#print axioms new_refines
#print axioms new_rejects
#print axioms update_refines
#print axioms finalize_refines
#print axioms authenticate_refines
#print axioms finalize_trace_refines
#print axioms finalize_trace_refines_concat

end Abc.Refine.HmacSha256.Implementation
