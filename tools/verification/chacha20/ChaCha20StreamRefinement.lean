import ChaCha20QuarterRoundRefinement
import ChaCha20Stream

namespace Abc.Refine.ChaCha20

open Aeneas Aeneas.Std
open Abc.Spec.ChaCha20

/-- Proof-only byte view of the successful output of the extracted block path.
The witness exists by the exact block theorem for every input. -/
private noncomputable def extractedBlock (key : Aeneas.Std.Array U8 32#usize)
    (nonce : Aeneas.Std.Array U8 12#usize) (counter : Word) : Bytes 64 :=
  let initial := Classical.choose_spec (block_from_bytes_refines key nonce ⟨counter⟩)
  byteView (Classical.choose initial)

/-- The provider bytes are observed in a successful extracted execution. -/
theorem extracted_block_provider_observes_result (key : Aeneas.Std.Array U8 32#usize)
    (nonce : Aeneas.Std.Array U8 12#usize) (counter : Word) :
    ∃ initial output,
      Abc.ChaCha20.Extracted.initial_state key nonce = .ok initial ∧
      Abc.ChaCha20.Extracted.block initial ⟨counter⟩ = .ok output ∧
      extractedBlock key nonce counter = byteView output := by
  let success := block_from_bytes_refines key nonce ⟨counter⟩
  let run := Classical.choose_spec (Classical.choose_spec success)
  exact ⟨Classical.choose success, Classical.choose (Classical.choose_spec success),
    run.1, run.2.1, rfl⟩

/-- The byte provider is the RFC block function for all counters, through
the checked Rust extraction of both initial-state and block creation. -/
theorem extracted_block_provider_refines (key : Aeneas.Std.Array U8 32#usize)
    (nonce : Aeneas.Std.Array U8 12#usize) :
    extractedBlock key nonce = blockBytes (byteView key) (byteView nonce) := by
  funext counter
  let initial := Classical.choose_spec (block_from_bytes_refines key nonce ⟨counter⟩)
  exact (Classical.choose_spec initial).2.2

/-- Compositional functional refinement of the stream model with the extracted
Rust block provider, covering every message byte and exhaustion status.
This theorem takes the logical schedule from `chunkedTransform`. It does not
assume a proof of the Rust mutable iterators that implement that schedule. -/
theorem extracted_chunked_stream_refines (key : Aeneas.Std.Array U8 32#usize)
    (nonce : Aeneas.Std.Array U8 12#usize) (counter : U32)
    {length : Nat} (input : Bytes length) :
    chunkedTransform (extractedBlock key nonce) counter.bv input =
      streamTransform (byteView key) (byteView nonce) counter.bv input := by
  rw [extracted_block_provider_refines]
  exact chunked_stream_refines (byteView key) (byteView nonce) counter.bv input

#print axioms extracted_block_provider_observes_result
#print axioms extracted_block_provider_refines
#print axioms extracted_chunked_stream_refines

end Abc.Refine.ChaCha20
