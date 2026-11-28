import HmacSpec
import StreamingRefinement

namespace Abc.Refine.HmacSha256.Prepared

open Abc.Spec.Sha256 (Byte Message State initial compress byteLengthAllowed digest)
open Abc.Spec.HmacSha256 (Error normalizeKey innerPad outerPad messageAllowed authenticate)
open Abc.Refine.Sha256.Streaming

structure KeyStates where
  inner : BufferView State
  outer : BufferView State

def start (processed : Message) : BufferView State :=
  (update compress ⟨initial, [], 0⟩ processed).2

def prepare (keyBlock : Message) : KeyStates :=
  ⟨start (innerPad keyBlock), start (outerPad keyBlock)⟩

/-- The working pad can be overwritten after absorbing the inner prefix. -/
theorem outer_from_inner (keyBlock : Message) :
    (innerPad keyBlock).map (fun byte => byte ^^^ ((0x36 : Byte) ^^^ 0x5c)) = outerPad keyBlock := by
  rw [innerPad, outerPad, List.map_map]
  congr 1
  funext byte
  change (byte ^^^ 0x36) ^^^ (0x36 ^^^ 0x5c) = byte ^^^ 0x5c
  rw [BitVec.xor_assoc byte, ← BitVec.xor_assoc (0x36 : Byte), BitVec.xor_self, BitVec.zero_xor]

def resume (state : BufferView State) (chunks : List Message) : BufferView State :=
  chunks.foldl (fun view input => (update compress view input).2) state

def finish (key : KeyStates) (state : BufferView State) : Message :=
  finalizeView (resume key.outer [finalizeView state])

theorem rep_start (processed : Message) (allowed : byteLengthAllowed processed.length) :
    Represents initial compress (start processed) processed := by
  simpa only [start, List.nil_append] using
    (update_preserves_representation (initial_represents initial compress) processed (by simpa using allowed)).2

theorem rep_inner (keyBlock : Message) (full : keyBlock.length = 64) :
    Represents initial compress (prepare keyBlock).inner (innerPad keyBlock) := by
  apply rep_start
  rw [Abc.Spec.HmacSha256.innerPad_length, full]
  decide

theorem rep_outer (keyBlock : Message) (full : keyBlock.length = 64) :
    Represents initial compress (prepare keyBlock).outer (outerPad keyBlock) := by
  apply rep_start
  rw [Abc.Spec.HmacSha256.outerPad_length, full]
  decide

/-- Resumption from the same saved state models a fresh HMAC message after each reset. -/
theorem resume_from_prefix {state : BufferView State} {processed : Message}
    (rep : Represents initial compress state processed) (chunks : List Message)
    (allowed : byteLengthAllowed (processed ++ chunks.flatten).length) :
    Represents initial compress (resume state chunks) (processed ++ chunks.flatten) := by
  rw [← acceptedTrace_eq_concat processed chunks allowed]
  exact trace_preserves_representation rep chunks

theorem rejected_update_preserves_context {state : BufferView State} {processed : Message}
    (rep : Represents initial compress state processed) (input : Message)
    (rejected : ¬ byteLengthAllowed (processed.length + input.length)) :
    update compress state input = (false, state) := by
  rcases rep with ⟨_, _, counter, allowed, _⟩
  exact update_rejects_without_mutation compress state input
    (by simpa [counter] using allowed) (by simpa [counter] using rejected)

theorem finish_refines (keyBlock : Message) (full : keyBlock.length = 64) (chunks : List Message)
    (allowed : messageAllowed chunks.flatten.length) :
    let key := prepare keyBlock
    let state := resume key.inner chunks
    let inner := finalizeView state
    some inner = digest (innerPad keyBlock ++ chunks.flatten) ∧
      some (finish key state) = digest (outerPad keyBlock ++ inner) := by
  let key := prepare keyBlock
  let state := resume key.inner chunks
  let inner := finalizeView state
  change some inner = digest (innerPad keyBlock ++ chunks.flatten) ∧
    some (finish key state) = digest (outerPad keyBlock ++ inner)
  have innerAllowed : byteLengthAllowed (innerPad keyBlock ++ chunks.flatten).length := by
    simpa [messageAllowed, full] using allowed
  have innerEq : some inner = digest (innerPad keyBlock ++ chunks.flatten) :=
    finalize_refines_digest (resume_from_prefix (rep_inner keyBlock full) chunks innerAllowed)
  have innerLength := Abc.Spec.HmacSha256.sha256_digest_length innerEq.symm
  have outerAllowed : byteLengthAllowed (outerPad keyBlock ++ [inner].flatten).length := by
    simp [full, innerLength]
    decide
  refine ⟨innerEq, ?_⟩
  simpa [finish, inner] using
    finalize_refines_digest (resume_from_prefix (rep_outer keyBlock full) [inner] outerAllowed)

def authenticateChunks (key : Message) (chunks : List Message) : Except Error Message :=
  match normalizeKey key with
  | none => .error .keyTooLong
  | some block =>
    if messageAllowed chunks.flatten.length then
      let saved := prepare block
      .ok (finish saved (resume saved.inner chunks))
    else .error .messageTooLong

theorem authenticateChunks_refines (key : Message) (chunks : List Message) :
    authenticateChunks key chunks = authenticate key chunks.flatten := by
  by_cases keyAllowed : byteLengthAllowed key.length
  · obtain ⟨block, normalized, full⟩ := Abc.Spec.HmacSha256.normalizeKey_accepted keyAllowed
    by_cases allowed : messageAllowed chunks.flatten.length
    · obtain ⟨innerEq, outerEq⟩ := finish_refines block full chunks allowed
      simp only [authenticateChunks, normalized, if_pos allowed, authenticate, ← innerEq, ← outerEq]
    · rw [Abc.Spec.HmacSha256.authenticate_message_rejected keyAllowed allowed]
      simp only [authenticateChunks, normalized, if_neg allowed]
  · simp only [authenticateChunks, Abc.Spec.HmacSha256.normalizeKey_rejected keyAllowed,
      Abc.Spec.HmacSha256.authenticate_key_rejected keyAllowed]

#print axioms resume_from_prefix
#print axioms outer_from_inner
#print axioms rejected_update_preserves_context
#print axioms finish_refines
#print axioms authenticateChunks_refines

end Abc.Refine.HmacSha256.Prepared
