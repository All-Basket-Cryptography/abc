import Refinement

namespace Abc.Sha256.TrustedClaims

open Aeneas.Std
open Abc.Spec.Sha256 (Message State)
open Abc.Refine.Sha256
open Abc.Sha256.Extracted (Sha256)

private def bytes (values : List U8) : Message := values.map U8.bv

private def registers (state : Aeneas.Std.Array U32 8#usize) : State :=
  ⟨(state.val[0]?.getD 0#u32).bv, (state.val[1]?.getD 0#u32).bv,
   (state.val[2]?.getD 0#u32).bv, (state.val[3]?.getD 0#u32).bv,
   (state.val[4]?.getD 0#u32).bv, (state.val[5]?.getD 0#u32).bv,
   (state.val[6]?.getD 0#u32).bv, (state.val[7]?.getD 0#u32).bv⟩

private def allowed (length : Nat) : Prop := 8 * length < 2 ^ 64

private instance (length : Nat) : Decidable (allowed length) :=
  inferInstanceAs (Decidable (8 * length < 2 ^ 64))

/-- The byte domain and padding are fixed independently of the implementation proof. -/
private def expectedDigest (message : Message) : Option Message :=
  if allowed message.length then
    let padded := message ++ [0x80] ++ List.replicate ((119 - message.length % 64) % 64) 0 ++
      Abc.Foundation.bytesBigEndian 8 (8 * message.length)
    some (Abc.Spec.Sha256.encode ((List.range (padded.length / 64)).foldl
      (fun state i => Abc.Spec.Sha256.compress state ((padded.drop (i * 64)).take 64))
      Abc.Spec.Sha256.initial))
  else none

private theorem digest_contract (message : Message) :
    Abc.Spec.Sha256.digest message = expectedDigest message := by
  simp only [Abc.Spec.Sha256.digest, Abc.Spec.Sha256.padding, expectedDigest, List.append_assoc]
  rfl

private def represents (state : Sha256) (message : Message) : Prop :=
  let pending := bytes (state.block.val.take state.buffered.val)
  ∃ blocks : List Message, blocks.flatten ++ pending = message ∧
    (∀ block ∈ blocks, block.length = 64) ∧ pending.length < 64 ∧
    state.length.val = message.length ∧ allowed message.length ∧
    registers state.state = blocks.foldl Abc.Spec.Sha256.compress Abc.Spec.Sha256.initial

private theorem representation_contract (state : Sha256) (message : Message) :
    Streaming.Represents Abc.Spec.Sha256.initial Abc.Spec.Sha256.compress
      (Implementation.streamView state) message ↔ represents state message := by
  constructor
  · rintro ⟨blocks, partition, length, fits, chaining⟩
    exact ⟨blocks, partition.reconstruct, partition.full, partition.short, length, fits, chaining⟩
  · rintro ⟨blocks, reconstruct, full, short, length, fits, chaining⟩
    exact ⟨blocks, ⟨reconstruct, full, short⟩, length, fits, chaining⟩

example : ∃ state, Sha256.new = .ok state ∧ represents state [] := by
  obtain ⟨state, created, representation⟩ := Implementation.new_refines
  exact ⟨state, created, (representation_contract state []).mp representation⟩

example (state : Aeneas.Std.Array U32 8#usize) (block : Slice U8) (full : block.val.length = 64) :
    ∃ out, Abc.Sha256.Extracted.compress state block = .ok out ∧
      registers out = Abc.Spec.Sha256.compress (registers state) (bytes block.val) :=
  Implementation.compress_refines state block full

example (state : Sha256) (message : Message) (input : Slice U8)
    (representation : represents state message) :
    ∃ result next, Sha256.update state input = .ok (result, next) ∧
      if allowed (message.length + (bytes input.val).length) then
        result = .Ok () ∧ represents next (message ++ bytes input.val)
      else result = .Err () ∧ next = state := by
  obtain ⟨⟨result, next⟩, updated, correct⟩ := WP.spec_imp_exists
    (Implementation.update_refines state message input ((representation_contract state message).mpr representation))
  refine ⟨result, next, updated, ?_⟩
  by_cases fits : Abc.Spec.Sha256.byteLengthAllowed (message.length + (Implementation.bytesView input.val).length)
  · simp only [if_pos fits] at correct
    simp only [if_pos (show allowed (message.length + (bytes input.val).length) from fits)]
    exact ⟨correct.1, (representation_contract next _).mp correct.2⟩
  · simp only [if_neg fits] at correct
    simp only [if_neg (show ¬ allowed (message.length + (bytes input.val).length) from fits)]
    cases correct
    exact ⟨rfl, rfl⟩

example (state : Sha256) (message : Message) (representation : represents state message) :
    ∃ out, Sha256.finalize state = .ok out ∧ some (bytes out.val) = expectedDigest message := by
  rw [← digest_contract]
  exact WP.spec_imp_exists (Implementation.finalize_refines state message
    ((representation_contract state message).mpr representation))

/-- Directly check the promise on both layers of the extracted Rust result. -/
example (input : Slice U8) :
    match expectedDigest (bytes input.val) with
    | none => Abc.Sha256.Extracted.digest input = .ok (.Err ())
    | some expected => ∃ out, Abc.Sha256.Extracted.digest input = .ok (.Ok out) ∧ bytes out.val = expected := by
  have correct := Implementation.digest_refines input
  rw [digest_contract] at correct
  cases ran : Abc.Sha256.Extracted.digest input with
  | ret result =>
    cases result with
    | Ok out =>
      simp only [Implementation.digestResultView, ran, bind_tc_ok] at correct
      have value : some (bytes out.val) = expectedDigest (bytes input.val) := Result.ok_injective correct
      rw [← value]
      exact ⟨out, rfl, rfl⟩
    | Err rejected =>
      cases rejected
      simp only [Implementation.digestResultView, ran, bind_tc_ok] at correct
      have value : none = expectedDigest (bytes input.val) := Result.ok_injective correct
      rw [← value]
  | vis effect continuation =>
    simp [Implementation.digestResultView, ran] at correct
  | div =>
    simp [Implementation.digestResultView, ran] at correct

private def appendAccepted (message chunk : Message) : Message :=
  if allowed (message.length + chunk.length) then message ++ chunk else message

private def updateAll (state : Sha256) (chunks : List (Slice U8)) : Result Sha256 :=
  match chunks with
  | [] => .ok state
  | chunk :: rest => do
    let (_, next) ← Sha256.update state chunk
    updateAll next rest

private theorem updateAll_contract (state : Sha256) (chunks : List (Slice U8)) :
    Implementation.runUpdates state chunks = updateAll state chunks := by
  induction chunks generalizing state with
  | nil => rfl
  | cons chunk rest ih => simp only [Implementation.runUpdates, updateAll, ih]

private def runTrace (chunks : List (Slice U8)) : Result (Aeneas.Std.Array U8 32#usize) := do
  let state ← Sha256.new
  let final ← updateAll state chunks
  Sha256.finalize final

private theorem trace_contract (chunks : List (Slice U8)) :
    Implementation.finalizeTrace chunks = runTrace chunks := by
  simp only [Implementation.finalizeTrace, runTrace, updateAll_contract]

example (chunks : List (Slice U8)) :
    ∃ out, runTrace chunks = .ok out ∧ some (bytes out.val) =
      expectedDigest ((chunks.map (fun chunk => bytes chunk.val)).foldl appendAccepted []) := by
  rw [← trace_contract, ← digest_contract]
  exact WP.spec_imp_exists (Implementation.finalize_trace_refines chunks)

example (chunks : List (Slice U8)) (fits : allowed (chunks.map (fun chunk => bytes chunk.val)).flatten.length) :
    ∃ out, runTrace chunks = .ok out ∧ some (bytes out.val) =
      expectedDigest (chunks.map (fun chunk => bytes chunk.val)).flatten := by
  rw [← trace_contract, ← digest_contract]
  exact WP.spec_imp_exists (Implementation.finalize_trace_refines_concat chunks fits)

end Abc.Sha256.TrustedClaims
