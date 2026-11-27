import CoreRefinement
import ExtractedCompression
import FinalizeRefinement
import UpdateRefinement

namespace Abc.Refine.Sha256.Implementation

open Aeneas Aeneas.Std
open Abc.Spec.Sha256

private theorem compressionSpec : CompressesAsSpec :=
  fun state block full => WP.exists_imp_spec (compress_refines state block full)

theorem finalize_refines : FinalizeRefines :=
  finalize_refines_of_compress compressionSpec

private theorem update_preserves : UpdatePreserves := by
  intro state message input represented
  obtain ⟨out, updated, correct⟩ := WP.spec_imp_exists (update_refines state message input represented)
  by_cases allowed : byteLengthAllowed (message.length + (bytesView input.val).length)
  · simp only [if_pos allowed] at correct
    rcases out with ⟨result, next⟩
    exact ⟨result, next, updated, by simpa only [Streaming.acceptedAppend, if_pos allowed] using correct.2⟩
  · simp only [if_neg allowed] at correct
    subst out
    exact ⟨.Err (), state, updated, by simpa only [Streaming.acceptedAppend, if_neg allowed] using represented⟩

theorem digest_refines (input : Slice U8) :
    digestResultView (Abc.Sha256.Extracted.digest input) = .ok (digest (bytesView input.val)) := by
  have represented : Streaming.Represents initial compress (streamView initialModel) [] := by
    rw [initial_streamView]
    exact Streaming.initial_represents initial compress
  refine digest_refines_from_steps input ?_ ?_ finalize_refines
  · intro allowed
    obtain ⟨⟨result, next⟩, updated, correct⟩ :=
      WP.spec_imp_exists (update_refines initialModel [] input represented)
    simp only [List.length_nil, Nat.zero_add, if_pos allowed, List.nil_append] at correct
    obtain ⟨resultEq, representedNext⟩ := correct
    subst result
    exact ⟨next, updated, representedNext⟩
  · intro rejected
    obtain ⟨out, updated, correct⟩ := WP.spec_imp_exists (update_refines initialModel [] input represented)
    simp only [List.length_nil, Nat.zero_add, if_neg rejected] at correct
    simpa only [correct] using updated

theorem finalize_trace_refines (chunks : List (Slice U8)) :
    finalizeTrace chunks ⦃ out => some (bytesView out.val) =
      digest ((chunks.map (fun input => bytesView input.val)).foldl Streaming.acceptedAppend []) ⦄ :=
  finalize_trace_refines_from_steps update_preserves finalize_refines chunks

theorem finalize_trace_refines_concat (chunks : List (Slice U8))
    (allowed : byteLengthAllowed (chunks.map (fun input => bytesView input.val)).flatten.length) :
    finalizeTrace chunks ⦃ out => some (bytesView out.val) =
      digest (chunks.map (fun input => bytesView input.val)).flatten ⦄ :=
  finalize_trace_refines_concat_from_steps update_preserves finalize_refines chunks allowed

#print axioms new_refines
#print axioms compress_refines
#print axioms update_refines
#print axioms finalize_refines
#print axioms digest_refines
#print axioms finalize_trace_refines
#print axioms finalize_trace_refines_concat

end Abc.Refine.Sha256.Implementation
