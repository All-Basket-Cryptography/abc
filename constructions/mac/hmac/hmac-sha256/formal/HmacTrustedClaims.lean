import HmacRefinement

namespace Abc.HmacSha256.TrustedClaims

open Aeneas Aeneas.Std
open Abc.HmacSha256.Extracted (HmacSha256 HmacError)
open Abc.Spec.Sha256 (Message)
open Abc.Refine.HmacSha256
open Abc.Refine.Sha256.Implementation (streamView)

private def bytes (slice : List U8) : Message := slice.map U8.bv

private def fitsKey (length : Nat) : Prop := 8 * length < 2 ^ 64
private def fitsInput (length : Nat) : Prop := 8 * (64 + length) < 2 ^ 64

private instance (length : Nat) : Decidable (fitsInput length) :=
  inferInstanceAs (Decidable (8 * (64 + length) < 2 ^ 64))

private def keyBlock (key : Message) : Option Message := do
  let material ← if key.length ≤ 64 then some key else Abc.Spec.Sha256.digest key
  some (material ++ List.replicate (64 - material.length) 0)

/-- Explicit RFC 2104 digest expressions and ABC's two domain errors. -/
private def expected (key message : Message) : Except Abc.Spec.HmacSha256.Error Message :=
  match keyBlock key with
  | none => .error .keyTooLong
  | some block =>
    match Abc.Spec.Sha256.digest ((block.map (fun byte => byte ^^^ 0x36)) ++ message) with
    | none => .error .messageTooLong
    | some innerHash =>
      match Abc.Spec.Sha256.digest ((block.map (fun byte => byte ^^^ 0x5c)) ++ innerHash) with
      | none => .error .messageTooLong
      | some tag => .ok tag

private theorem expected_eq (key input : Message) :
    Abc.Spec.HmacSha256.authenticate key input = expected key input := rfl

private def hashState (state : Abc.Sha256.Extracted.Sha256) (message : Message) : Prop :=
  Abc.Refine.Sha256.Streaming.Represents Abc.Spec.Sha256.initial Abc.Spec.Sha256.compress
    (streamView state) message

private def represents (state : HmacSha256) (key message : Message) : Prop :=
  key.length = 64 ∧
    hashState state.inner (key.map (fun byte => byte ^^^ 0x36) ++ message) ∧
    hashState state.outer (key.map (fun byte => byte ^^^ 0x5c))

private theorem representation_eq (state : HmacSha256) (key message : Message) :
    Implementation.Represents state key message ↔ represents state key message := by
  constructor
  · rintro ⟨length, inner, outer⟩
    exact ⟨length, inner, outer⟩
  · rintro ⟨length, inner, outer⟩
    exact ⟨length, inner, outer⟩

example (key : Slice U8) (fits : fitsKey (bytes key.val).length) :
    ∃ state normalized, HmacSha256.new key = .ok (.Ok state) ∧
      keyBlock (bytes key.val) = some normalized ∧ represents state normalized [] := by
  obtain ⟨state, normalized, created, block, represented⟩ := Implementation.new_refines key fits
  exact ⟨state, normalized, created, block, (representation_eq state normalized []).mp represented⟩

example (key : Slice U8) (rejected : ¬ fitsKey (bytes key.val).length) :
    HmacSha256.new key = .ok (.Err .KeyTooLong) := Implementation.new_rejects key rejected

example (state : HmacSha256) (key message : Message) (input : Slice U8)
    (representation : represents state key message) :
    ∃ result next, HmacSha256.update state input = .ok (result, next) ∧
      if fitsInput (message.length + (bytes input.val).length) then
        result = .Ok () ∧ represents next key (message ++ bytes input.val)
      else result = .Err .MessageTooLong ∧ next = state := by
  obtain ⟨⟨result, next⟩, updated, correct⟩ := WP.spec_imp_exists
    (Implementation.update_refines state key message input ((representation_eq state key message).mpr representation))
  refine ⟨result, next, updated, ?_⟩
  by_cases allowed : fitsInput (message.length + (bytes input.val).length)
  · have domain : Abc.Spec.HmacSha256.messageAllowed
        (message.length + (Abc.Refine.Sha256.Implementation.bytesView input.val).length) := allowed
    simp only [if_pos domain] at correct
    simp only [if_pos allowed]
    exact ⟨correct.1, (representation_eq next key _).mp correct.2⟩
  · have domain : ¬ Abc.Spec.HmacSha256.messageAllowed
        (message.length + (Abc.Refine.Sha256.Implementation.bytesView input.val).length) := allowed
    simp only [if_neg domain] at correct
    simp only [if_neg allowed]
    cases correct
    exact ⟨rfl, rfl⟩

example (state : HmacSha256) (key normalized message : Message)
    (block : keyBlock key = some normalized) (representation : represents state normalized message) :
    ∃ tag, HmacSha256.finalize state = .ok (.Ok tag) ∧ expected key message = .ok (bytes tag.val) := by
  rw [← expected_eq]
  exact Implementation.finalize_refines state key normalized message block
    ((representation_eq state normalized message).mpr representation)

private abbrev RustTag := core.result.Result (Aeneas.Std.Array U8 32#usize) HmacError

private def exactOutcome (call : Result RustTag) (promised : Except Abc.Spec.HmacSha256.Error Message) : Prop :=
  match promised with
  | .ok tag => ∃ out, call = .ok (.Ok out) ∧ bytes out.val = tag
  | .error .keyTooLong => call = .ok (.Err .KeyTooLong)
  | .error .messageTooLong => call = .ok (.Err .MessageTooLong)

private theorem exactOutcome_of_spec (call : Result RustTag) (promised : Except Abc.Spec.HmacSha256.Error Message)
    (correct : call ⦃ result => Implementation.viewResult result = promised ⦄) :
    exactOutcome call promised := by
  obtain ⟨result, ran, value⟩ := WP.spec_imp_exists correct
  rw [← value]
  cases result with
  | Ok tag => exact ⟨tag, ran, rfl⟩
  | Err error => cases error <;> exact ran

example (key input : Slice U8) :
    exactOutcome (Abc.HmacSha256.Extracted.authenticate key input) (expected (bytes key.val) (bytes input.val)) := by
  apply exactOutcome_of_spec
  rw [← expected_eq]
  exact Implementation.authenticate_refines key input

private def appendIfFits (prior chunk : Message) : Message :=
  if fitsInput (prior.length + chunk.length) then prior ++ chunk else prior

private def callUpdates (state : HmacSha256) (chunks : List (Slice U8)) : Result HmacSha256 :=
  match chunks with
  | [] => .ok state
  | input :: rest => do
    let (_, next) ← HmacSha256.update state input
    callUpdates next rest

private theorem callUpdates_eq (state : HmacSha256) (chunks : List (Slice U8)) :
    Implementation.updateAll state chunks = callUpdates state chunks := by
  induction chunks generalizing state with
  | nil => rfl
  | cons input rest ih => simp only [Implementation.updateAll, callUpdates, ih]

private def callTrace (key : Slice U8) (chunks : List (Slice U8)) : Result RustTag := do
  let initialized ← HmacSha256.new key
  match initialized with
  | .Err error => .ok (.Err error)
  | .Ok state =>
    let final ← callUpdates state chunks
    HmacSha256.finalize final

private theorem callTrace_eq (key : Slice U8) (chunks : List (Slice U8)) :
    Implementation.finalizeTrace key chunks = callTrace key chunks := by
  simp only [Implementation.finalizeTrace, callTrace, callUpdates_eq]
  rfl

example (key : Slice U8) (chunks : List (Slice U8)) :
    exactOutcome (callTrace key chunks)
      (expected (bytes key.val) ((chunks.map (fun input => bytes input.val)).foldl appendIfFits [])) := by
  apply exactOutcome_of_spec
  rw [← callTrace_eq, ← expected_eq]
  exact Implementation.finalize_trace_refines key chunks

example (key : Slice U8) (chunks : List (Slice U8))
    (fits : fitsInput (chunks.map (fun input => bytes input.val)).flatten.length) :
    exactOutcome (callTrace key chunks)
      (expected (bytes key.val) (chunks.map (fun input => bytes input.val)).flatten) := by
  apply exactOutcome_of_spec
  rw [← callTrace_eq, ← expected_eq]
  exact Implementation.finalize_trace_refines_concat key chunks fits

end Abc.HmacSha256.TrustedClaims
