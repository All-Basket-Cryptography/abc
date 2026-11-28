import Abc.Sha256.Extracted.Funs
import ModelView

namespace Abc.Refine.Sha256.Implementation

open Aeneas Aeneas.Std
open Abc.Spec.Sha256

/-- The value returned by the generated Rust constructor. -/
def initialModel : Abc.Sha256.Extracted.Sha256 :=
  { state := Abc.Sha256.Extracted.INITIAL_STATE
    block := Aeneas.Std.Array.repeat 64#usize 0#u8
    buffered := 0#usize
    length := 0#u64 }

theorem new_eq : Abc.Sha256.Extracted.Sha256.new = .ok initialModel := rfl

theorem initial_streamView : streamView initialModel = ⟨initial, [], 0⟩ := by
  simp [streamView, initialModel, stateView, Abc.Sha256.Extracted.INITIAL_STATE, initial, bytesView]

theorem new_refines :
    ∃ rust, Abc.Sha256.Extracted.Sha256.new = .ok rust ∧
      Streaming.Represents initial compress (streamView rust) [] := by
  refine ⟨initialModel, new_eq, ?_⟩
  rw [initial_streamView]
  exact Streaming.initial_represents initial compress

/-- The Rust success payload represents its digest bytes. The Rust length
    error represents the specification's rejection. -/
def digestResultView
    (rust : Result (core.result.Result (Aeneas.Std.Array U8 32#usize)
      Abc.Sha256.Extracted.MessageTooLong)) : Result (Option Message) := do
  let translated ← rust
  match translated with
  | .Ok value => .ok (some (bytesView value.val))
  | .Err _ => .ok none

theorem digest_of_update_ok (input : Slice U8) (state : Abc.Sha256.Extracted.Sha256)
    (output : Aeneas.Std.Array U8 32#usize)
    (updated : Abc.Sha256.Extracted.Sha256.update initialModel input = .ok (.Ok (), state))
    (finalized : Abc.Sha256.Extracted.Sha256.finalize state = .ok output) :
    Abc.Sha256.Extracted.digest input = .ok (.Ok output) := by
  simp [Abc.Sha256.Extracted.digest, new_eq, updated, core.result.Result.Insts.CoreOpsTry.branch,
    finalized]

theorem digest_of_update_error (input : Slice U8) (state : Abc.Sha256.Extracted.Sha256)
    (updated : Abc.Sha256.Extracted.Sha256.update initialModel input = .ok (.Err (), state)) :
    Abc.Sha256.Extracted.digest input = .ok (.Err ()) := by
  simp [Abc.Sha256.Extracted.digest, new_eq, updated, core.result.Result.Insts.CoreOpsTry.branch,
    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
    core.convert.FromSame.from]

def FinalizeRefines : Prop :=
  ∀ (state : Abc.Sha256.Extracted.Sha256) (message : Message),
    Streaming.Represents initial compress (streamView state) message →
    Abc.Sha256.Extracted.Sha256.finalize state
      ⦃ out => some (bytesView out.val) = digest message ⦄

/-- Compose the independent update and finalization contracts with the exact
    constructor and one-shot entry point. -/
theorem digest_refines_from_steps (input : Slice U8)
    (acceptUpdate : byteLengthAllowed (bytesView input.val).length →
      ∃ state, Abc.Sha256.Extracted.Sha256.update initialModel input = .ok (.Ok (), state) ∧
        Streaming.Represents initial compress (streamView state) (bytesView input.val))
    (rejectUpdate : ¬ byteLengthAllowed (bytesView input.val).length →
      Abc.Sha256.Extracted.Sha256.update initialModel input = .ok (.Err (), initialModel))
    (finalizeRefines : FinalizeRefines) :
    digestResultView (Abc.Sha256.Extracted.digest input) =
      .ok (digest (bytesView input.val)) := by
  by_cases allowed : byteLengthAllowed (bytesView input.val).length
  · obtain ⟨state, updated, represented⟩ := acceptUpdate allowed
    obtain ⟨out, finalized, bytes⟩ := WP.spec_imp_exists (finalizeRefines state _ represented)
    rw [digest_of_update_ok input state out updated finalized]
    simpa only [digestResultView, Aeneas.Std.bind_tc_ok] using congrArg Result.ok bytes
  · rw [digest_of_update_error input initialModel (rejectUpdate allowed)]
    simp only [digestResultView, Aeneas.Std.bind_tc_ok, digest, if_neg allowed]

/-- Execute the Rust updates in order, keeping the returned state after
    each Rust success or recoverable length error. -/
def runUpdates :
    Abc.Sha256.Extracted.Sha256 → List (Slice U8) → Result Abc.Sha256.Extracted.Sha256
  | state, [] => .ok state
  | state, input :: remaining => do
    let (_, next) ← Abc.Sha256.Extracted.Sha256.update state input
    runUpdates next remaining

def UpdatePreserves : Prop :=
  ∀ (state : Abc.Sha256.Extracted.Sha256) (message : Message) (input : Slice U8),
    Streaming.Represents initial compress (streamView state) message →
    ∃ result next, Abc.Sha256.Extracted.Sha256.update state input = .ok (result, next) ∧
      Streaming.Represents initial compress (streamView next)
        (Streaming.acceptedAppend message (bytesView input.val))

/-- A checked single-update refinement lifts to every finite call trace. -/
theorem runUpdates_refines_from_step
    (stepRefines : UpdatePreserves)
    (state : Abc.Sha256.Extracted.Sha256) (message : Message) (chunks : List (Slice U8))
    (represented : Streaming.Represents initial compress (streamView state) message) :
    ∃ next, runUpdates state chunks = .ok next ∧
      Streaming.Represents initial compress (streamView next)
        ((chunks.map (fun input => bytesView input.val)).foldl Streaming.acceptedAppend message) := by
  induction chunks generalizing state message with
  | nil => exact ⟨state, rfl, represented⟩
  | cons input remaining onward =>
    obtain ⟨result, next, updated, representedNext⟩ := stepRefines state message input represented
    obtain ⟨out, ran, representedOut⟩ := onward next _ representedNext
    refine ⟨out, ?_, representedOut⟩
    simp [runUpdates, updated, ran]

/-- Execute a fresh Rust constructor, every streaming update, and finalization. -/
def finalizeTrace (chunks : List (Slice U8)) : Result (Aeneas.Std.Array U8 32#usize) := do
  let initialState ← Abc.Sha256.Extracted.Sha256.new
  let finalState ← runUpdates initialState chunks
  Abc.Sha256.Extracted.Sha256.finalize finalState

/-- The exact API call trace produces the digest of all accepted chunks. -/
theorem finalize_trace_refines_from_steps (stepRefines : UpdatePreserves)
    (finalizeRefines : FinalizeRefines) (chunks : List (Slice U8)) :
    finalizeTrace chunks ⦃ out => some (bytesView out.val) =
      digest ((chunks.map (fun input => bytesView input.val)).foldl Streaming.acceptedAppend []) ⦄ := by
  obtain ⟨state, constructed, represented⟩ := new_refines
  obtain ⟨finalState, ran, representedFinal⟩ :=
    runUpdates_refines_from_step stepRefines state [] chunks represented
  simpa only [finalizeTrace, constructed, ran, Aeneas.Std.bind_tc_ok] using
    (finalizeRefines finalState _ representedFinal)

theorem finalize_trace_refines_concat_from_steps (stepRefines : UpdatePreserves)
    (finalizeRefines : FinalizeRefines) (chunks : List (Slice U8))
    (allowed : byteLengthAllowed (chunks.map (fun input => bytesView input.val)).flatten.length) :
    finalizeTrace chunks ⦃ out => some (bytesView out.val) =
      digest (chunks.map (fun input => bytesView input.val)).flatten ⦄ := by
  have accepted := Streaming.acceptedTrace_eq_concat []
    (chunks.map (fun input => bytesView input.val)) (by simpa using allowed)
  simpa only [accepted, List.nil_append] using
    finalize_trace_refines_from_steps stepRefines finalizeRefines chunks

end Abc.Refine.Sha256.Implementation
