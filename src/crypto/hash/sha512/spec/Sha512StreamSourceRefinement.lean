import Sha512StreamLlbc

namespace Abc.Refine.Sha512.StreamSource

open Abc.Spec.Sha512 (Byte Message byteLengthAllowed)
open Abc.Refine.Sha512.Streaming

theorem sourceRejects_refines (prior incoming : Nat)
    (priorValid : byteLengthAllowed prior) (fitsSlice : incoming < 2 ^ 64) :
    sourceRejects prior incoming ↔ ¬ byteLengthAllowed (prior + incoming) := by
  unfold sourceRejects byteLengthAllowed at *
  rw [Nat.mod_eq_of_lt (by omega : incoming < 2 ^ 128)]
  omega

theorem sourceCount_refines (prior incoming : Nat) (fitsSlice : incoming < 2 ^ 64) :
    sourceCount prior incoming = prior + incoming := by
  unfold sourceCount
  rw [Nat.mod_eq_of_lt (by omega : incoming < 2 ^ 128)]

theorem acceptedCounterFits (prior incoming : Nat) (priorValid : byteLengthAllowed prior)
    (fitsSlice : incoming < 2 ^ 64) (admitted : ¬ sourceRejects prior incoming) :
    sourceCount prior incoming < 2 ^ 128 := by
  rw [sourceCount_refines _ _ fitsSlice]
  rw [sourceRejects_refines _ _ priorValid fitsSlice] at admitted
  unfold byteLengthAllowed at admitted
  omega

/-- Attach the generated branch and counter to the reviewed update block driver. -/
def updateWithSourceGate {α : Type} (compress : α → Message → α)
    (view : BufferView α) (input : Message) : Bool × BufferView α :=
  if sourceRejects view.length input.length then (false, view)
  else
    let split := splitBlocks (view.pending ++ input)
    (true, ⟨split.1.foldl compress view.chaining, split.2, sourceCount view.length input.length⟩)

theorem updateWithSourceGate_refines {α : Type} (compress : α → Message → α)
    (view : BufferView α) (input : Message) (priorValid : byteLengthAllowed view.length)
    (fitsSlice : input.length < 2 ^ 64) :
    updateWithSourceGate compress view input = update compress view input := by
  rw [updateWithSourceGate, update, checkedLength_matches_domain _ _ priorValid,
    sourceCount_refines _ _ fitsSlice]
  by_cases admitted : byteLengthAllowed (view.length + input.length)
  · have branch : ¬ sourceRejects view.length input.length :=
      fun rejected => (sourceRejects_refines _ _ priorValid fitsSlice).mp rejected admitted
    simp only [if_neg branch, if_pos admitted]
  · have branch : sourceRejects view.length input.length :=
      (sourceRejects_refines _ _ priorValid fitsSlice).mpr admitted
    simp only [if_pos branch, if_neg admitted]

theorem rejectedUpdate_preservesView {α : Type} (compress : α → Message → α)
    (view : BufferView α) (input : Message) (priorValid : byteLengthAllowed view.length)
    (fitsSlice : input.length < 2 ^ 64)
    (rejected : ¬ byteLengthAllowed (view.length + input.length)) :
    updateWithSourceGate compress view input = (false, view) := by
  rw [updateWithSourceGate_refines _ _ _ priorValid fitsSlice]
  exact update_rejects_without_mutation compress view input priorValid rejected

def sourceLengthBytes (prior : Nat) : Message :=
  Abc.Foundation.bytesBigEndian 16 (sourceBitLength prior)

theorem sourceBitLengthFits (prior : Nat) (valid : byteLengthAllowed prior) :
    sourceBitLength prior < 2 ^ 128 :=
  bitLength_fits prior valid

def markedAndCleared (storage : Message) (buffered : Nat) : Message :=
  let marked := overwriteWindow storage (sourceMarkerAt buffered) [sourceMarker]
  marked.take (sourceZeroAt buffered) ++
    List.replicate (sourceCapacity - sourceZeroAt buffered) sourceZero

theorem markedAndCleared_eq (storage : Message) (buffered : Nat)
    (width : storage.length = 128) (short : buffered < 128) :
    markedAndCleared storage buffered =
      storage.take buffered ++ [0x80] ++ List.replicate (127 - buffered) 0 := by
  have copies : (overwriteWindow storage buffered [0x80]).take (buffered + 1) =
      storage.take buffered ++ [0x80] :=
    overwrittenPrefix storage [0x80] buffered (by omega)
  have remaining : 128 - (buffered + 1) = 127 - buffered := by omega
  simp only [markedAndCleared, sourceMarkerAt, sourceMarker, sourceZeroAt, sourceCapacity,
    sourceZero, copies, remaining]

def emittedBlocks (storage : Message) (buffered prior : Nat) : List Message :=
  let first := markedAndCleared storage buffered
  let suffix := sourceLengthBytes prior
  if sourceExtraBlock buffered then
    [first, (List.replicate sourceCapacity sourceReset).take sourceLengthAt ++ suffix]
  else
    [first.take sourceLengthAt ++ suffix]

theorem emittedBlocks_refines (storage : Message) (buffered prior : Nat)
    (width : storage.length = 128) (short : buffered < 128) :
    emittedBlocks storage buffered prior = finalBlocks (storage.take buffered) prior := by
  have headSize : (storage.take buffered).length = buffered := by
    simp [Nat.min_eq_left (by omega : buffered ≤ storage.length)]
  rw [emittedBlocks, markedAndCleared_eq storage buffered width short]
  simp only [sourceExtraBlock, sourceCapacity, sourceReset, sourceLengthAt, sourceLengthBytes,
    sourceBitLength, finalBlocks, headSize]
  by_cases single : buffered < 112
  · have noExtra : ¬ buffered ≥ 112 := by omega
    rw [if_neg noExtra, if_pos single]
    have headAndMarker : (storage.take buffered ++ ([0x80] : Message)).length = buffered + 1 := by
      simp [headSize]
    have headFits : (storage.take buffered ++ ([0x80] : Message)).length ≤ 112 := by omega
    rw [List.take_append, List.take_of_length_le headFits, headAndMarker, List.take_replicate]
    have remaining : 112 - (buffered + 1) = 111 - buffered := by omega
    rw [remaining, Nat.min_eq_left (by omega : 111 - buffered ≤ 127 - buffered)]
  · have extra : buffered ≥ 112 := by omega
    rw [if_pos extra, if_neg single, List.take_replicate]
    rfl

theorem emittedBlocks_byte_contract (storage message : Message) (buffered : Nat)
    (width : storage.length = 128) (short : buffered < 128)
    (remainder : message.length % 128 = buffered) :
    (emittedBlocks storage buffered message.length).flatten =
      storage.take buffered ++ Abc.Spec.Sha512.padding message.length := by
  rw [emittedBlocks_refines _ _ _ width short]
  have headSize : (storage.take buffered).length = buffered := by
    simp [Nat.min_eq_left (by omega : buffered ≤ storage.length)]
  exact finalBlocks_bytes message (storage.take buffered) (by omega) (by simpa only [headSize] using remainder)

/-- Connect the generated final blocks to the portable compression and digest encoder model. -/
def finalizeWithSourcePadding (storage : Message) (view : BufferView Registers) : Message :=
  encodeRegisters ((emittedBlocks storage view.pending.length view.length).foldl
    Abc.Refine.Sha512.compress view.chaining)

theorem finalizeWithSourcePadding_refines (storage message : Message) (view : BufferView Registers)
    (width : storage.length = 128) (short : view.pending.length < 128)
    (prefixMatches : storage.take view.pending.length = view.pending)
    (representation : Represents initialRegisters Abc.Refine.Sha512.compress view message) :
    some (finalizeWithSourcePadding storage view) = Abc.Spec.Sha512.digest message := by
  rw [finalizeWithSourcePadding, emittedBlocks_refines _ _ _ width short, prefixMatches]
  exact finalize_refines_digest representation

#print axioms sourceRejects_refines
#print axioms sourceCount_refines
#print axioms acceptedCounterFits
#print axioms updateWithSourceGate_refines
#print axioms rejectedUpdate_preservesView
#print axioms sourceBitLengthFits
#print axioms emittedBlocks_refines
#print axioms emittedBlocks_byte_contract
#print axioms finalizeWithSourcePadding_refines

end Abc.Refine.Sha512.StreamSource
