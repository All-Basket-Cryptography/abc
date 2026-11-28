import Sha512ApiLlbc

namespace Abc.Refine.Sha512.ApiSource

open Abc.Spec.Sha512 (Message byteLengthAllowed)
open Abc.Refine.Sha512.Streaming
open Abc.Refine.Sha512.StreamSource

private theorem overwriteWindow_size (storage input : Message) (offset : Nat)
    (valid : offset + input.length ≤ storage.length) :
    (overwriteWindow storage offset input).length = storage.length := by
  simp only [overwriteWindow, List.length_append, List.length_take, List.length_drop]
  rw [Nat.min_eq_left (by omega : offset ≤ storage.length)]
  omega

theorem sourceCopied_refines (incoming buffered : Nat) :
    sourceCopied incoming buffered = min incoming (128 - buffered) := by
  rfl

theorem sourceInitial_refines :
    sourceInitialRegisters = initialRegisters ∧ sourceInitialStorage.length = 128 ∧
      sourceInitialStorage.take sourceInitialBuffered = [] ∧ sourceInitialPrior = 0 := by
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem sourceEncode_refines (r : Registers) : sourceEncode r = encodeRegisters r := by
  rfl

private theorem sourceChunkTail_refines (storage remaining : Message) (complete : List Message)
    (width : storage.length = 128) :
    let out := sourceChunkTail storage complete remaining
    out.storage.length = 128 ∧
      (out.emitted, out.storage.take out.buffered) =
        (complete ++ (splitBlocks remaining).1, (splitBlocks remaining).2) := by
  have short := (splitBlocks_partition remaining).short
  have window : 0 + (splitBlocks remaining).2.length ≤ storage.length := by omega
  have copied := overwrittenPrefix storage (splitBlocks remaining).2 0 (by omega)
  simp only [Nat.zero_add, List.take_zero, List.nil_append] at copied
  simp only [sourceChunkTail, overwriteWindow_size _ _ _ window, width, copied, and_self]

theorem sourceDriver_refines (storage input : Message) (buffered : Nat)
    (width : storage.length = 128) (short : buffered < 128) :
    let out := sourceDriver storage buffered input
    out.storage.length = 128 ∧ out.buffered < 128 ∧
      (out.emitted, out.storage.take out.buffered) = splitBlocks (storage.take buffered ++ input) := by
  let pending := storage.take buffered
  have pendingSize : pending.length = buffered := List.length_take_of_le (by omega)
  change (sourceDriver storage buffered input).storage.length = 128 ∧
    (sourceDriver storage buffered input).buffered < 128 ∧
    ((sourceDriver storage buffered input).emitted,
      (sourceDriver storage buffered input).storage.take (sourceDriver storage buffered input).buffered) =
        splitBlocks (pending ++ input)
  by_cases isEmpty : buffered = 0
  · have tail := sourceChunkTail_refines storage input [] width
    have tailShort : (sourceChunkTail storage [] input).buffered < 128 := (splitBlocks_partition input).short
    rw [isEmpty, sourceDriver, if_neg (by decide : ¬ sourceHasPending 0)]
    refine ⟨tail.1, tailShort, ?_⟩
    simpa only [pending, isEmpty, List.take_zero, List.nil_append] using tail.2
  · have active : sourceHasPending buffered := isEmpty
    rw [sourceDriver, if_pos active]
    have stops : sourceStops input.length buffered ↔ input.length < 128 - buffered := by
      unfold sourceStops
      omega
    by_cases small : input.length < 128 - buffered
    · have copied : sourceCopied input.length buffered = input.length := by
        rw [sourceCopied_refines, Nat.min_eq_left (by omega)]
      have endAt : sourceEnd input.length buffered = buffered + input.length := by
        change buffered + sourceCopied input.length buffered = _
        rw [copied]
      rw [if_pos (stops.mpr small), copied, endAt, List.take_length]
      constructor
      · rw [overwriteWindow_size _ _ _ (by omega), width]
      constructor
      · dsimp
        omega
      · have split := fill_buffer_short pending input (by omega) (by omega)
        rw [pendingSize, Nat.min_eq_right (by omega), List.take_length] at split
        rw [split]
        exact congrArg (fun suffix => ([], suffix)) (overwrittenPrefix storage input buffered (by omega))
    · let room := 128 - buffered
      have fits : room ≤ input.length := by omega
      have copied : sourceCopied input.length buffered = room := by
        rw [sourceCopied_refines, Nat.min_eq_right fits]
      let written := overwriteWindow storage buffered (input.take room)
      have piece : (input.take room).length = room := List.length_take_of_le fits
      have writtenWidth : written.length = 128 := by
        change (overwriteWindow storage buffered (input.take room)).length = 128
        rw [overwriteWindow_size _ _ _ (by omega), width]
      have writtenEq : written = pending ++ input.take room := by
        have copiedPrefix := overwrittenPrefix storage (input.take room) buffered (by omega)
        have exactly : buffered + (input.take room).length = 128 := by omega
        have takeFull : written.take 128 = written := List.take_of_length_le (by omega)
        rw [exactly] at copiedPrefix
        exact takeFull.symm.trans copiedPrefix
      rw [if_neg (fun stopsHere => small (stops.mp stopsHere)), copied]
      have tail := sourceChunkTail_refines written (input.drop room) [written] writtenWidth
      have tailShort : (sourceChunkTail written [written] (input.drop room)).buffered < 128 :=
        (splitBlocks_partition (input.drop room)).short
      refine ⟨tail.1, tailShort, tail.2.trans ?_⟩
      rw [fill_buffer_full pending input (by omega) (by omega), pendingSize, writtenEq]
      rfl

theorem sourceDigest_refines (message : Message) (fitsInput : message.length < 2 ^ 64) :
    sourceDigest message = Abc.Spec.Sha512.digest message := by
  have initialValid : byteLengthAllowed 0 := by decide
  have gate := sourceRejects_refines 0 message.length initialValid fitsInput
  rw [Nat.zero_add] at gate
  have sameCompression : Llbc.generatedCompression = Abc.Refine.Sha512.compress :=
    funext (fun state => funext (Llbc.generatedCompression_eq state))
  rw [sourceDigest, sameCompression, sourceDigestUsing, sourceInitial_refines.2.2.2]
  by_cases allowed : byteLengthAllowed message.length
  · have admit : ¬ sourceRejects 0 message.length := fun rejects => gate.mp rejects allowed
    have driver := sourceDriver_refines sourceInitialStorage message sourceInitialBuffered
      sourceInitial_refines.2.1 (by decide)
    simp only [sourceInitial_refines.2.2.1, List.nil_append] at driver
    rw [if_neg admit, sourceInitial_refines.1, sourceCount_refines _ _ fitsInput, Nat.zero_add]
    dsimp only
    rw [sourceEncode_refines, emittedBlocks_refines _ _ _ driver.1 driver.2.1]
    have blocks := congrArg Prod.fst driver.2.2
    have tail := congrArg Prod.snd driver.2.2
    dsimp only at blocks tail
    rw [blocks, tail]
    have preserves := update_preserves_representation
      (initial_represents initialRegisters Abc.Refine.Sha512.compress) message (by simpa using allowed)
    have updateOk : checkedLength 0 message.length = some message.length := by
      rw [checkedLength_matches_domain _ _ initialValid, Nat.zero_add, if_pos allowed]
    simp only [update, updateOk, List.nil_append] at preserves
    exact finalize_refines_digest preserves.2
  · rw [if_pos (gate.mpr allowed), Abc.Spec.Sha512.digest, if_neg allowed]

#print axioms sourceCopied_refines
#print axioms sourceInitial_refines
#print axioms sourceEncode_refines
#print axioms sourceDriver_refines
#print axioms sourceDigest_refines

end Abc.Refine.Sha512.ApiSource
