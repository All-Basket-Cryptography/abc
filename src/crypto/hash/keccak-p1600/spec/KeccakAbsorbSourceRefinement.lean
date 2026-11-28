import KeccakAbsorbLlbc

namespace Abc.Refine.Keccak.AbsorbSource

open Abc.Spec.KeccakRound
open Abc.Spec.Keccak.Reader (Cursor)
open Abc.Spec.Keccak.SpongeRead (wordByte specBit)
open Abc.Refine.Keccak.Source
open Abc.Refine.Keccak.WrapperSource
open Abc.Refine.Keccak.ReaderSource

abbrev Message := List Byte

/-- Split bytes into complete 136-byte blocks and a short suffix. -/
def splitBlocks (bytes : Message) : List Message × Message :=
  if bytes.length < 136 then ([], bytes) else
    let rest := splitBlocks (bytes.drop 136)
    (bytes.take 136 :: rest.1, rest.2)
termination_by bytes.length
decreasing_by simp; omega

structure Partition (bytes : Message) (blocks : List Message) (pending : Message) : Prop where
  reconstruct : blocks.flatten ++ pending = bytes
  full : ∀ block ∈ blocks, block.length = 136
  short : pending.length < 136

theorem splitBlocks_partition (bytes : Message) :
    Partition bytes (splitBlocks bytes).1 (splitBlocks bytes).2 := by
  rw [splitBlocks]
  split
  next short =>
    exact ⟨rfl, by simp, short⟩
  next enough =>
    have tail := splitBlocks_partition (bytes.drop 136)
    constructor
    · simp only [List.flatten_cons, List.append_assoc, tail.reconstruct, List.take_append_drop]
    · intro block member
      rcases List.mem_cons.mp member with equal | later
      · subst block
        simp only [List.length_take]
        omega
      · exact tail.full block later
    · exact tail.short
termination_by bytes.length
decreasing_by simp; omega

theorem Partition.feed {message pending : Message} {blocks : List Message}
    (partition : Partition message blocks pending) (input : Message) :
    Partition (message ++ input) (blocks ++ (splitBlocks (pending ++ input)).1)
      (splitBlocks (pending ++ input)).2 := by
  have fresh := splitBlocks_partition (pending ++ input)
  constructor
  · simp only [List.flatten_append, List.append_assoc, fresh.reconstruct]
    rw [← List.append_assoc, partition.reconstruct]
  · intro block member
    exact (List.mem_append.mp member).elim (partition.full block) (fresh.full block)
  · exact fresh.short

/-- The successful write view keeps only the previously initialized prefix and new bytes. -/
def overwriteWindow (storage : Message) (offset : Nat) (input : Message) : Message :=
  storage.take offset ++ input ++ storage.drop (offset + input.length)

theorem overwrittenPrefix (storage input : Message) (offset : Nat) (valid : offset ≤ storage.length) :
    (overwriteWindow storage offset input).take (offset + input.length) =
      storage.take offset ++ input := by
  have prefixLength : (storage.take offset ++ input).length = offset + input.length := by
    simp [Nat.min_eq_left valid]
  rw [overwriteWindow, ← prefixLength, List.take_append_length]

/-- If the Rust update exits early after filling part of its pending block, no block is emitted. -/
theorem fill_buffer_short (pending input : Message) (short : pending.length < 136)
    (inputShort : input.length < 136 - pending.length) :
    splitBlocks (pending ++ input) =
      ([], pending ++ input.take (min (136 - pending.length) input.length)) := by
  have lengthShort : (pending ++ input).length < 136 := by simp; omega
  rw [splitBlocks, if_pos lengthShort, Nat.min_eq_right (by omega)]
  simp

/-- A completed pending block is emitted before splitting the remaining input into blocks. -/
theorem fill_buffer_full (pending input : Message) (short : pending.length < 136)
    (enough : 136 - pending.length ≤ input.length) :
    splitBlocks (pending ++ input) =
      ((pending ++ input.take (136 - pending.length)) ::
        (splitBlocks (input.drop (136 - pending.length))).1,
        (splitBlocks (input.drop (136 - pending.length))).2) := by
  have lengthFull : ¬ (pending ++ input).length < 136 := by simp; omega
  have takePending : pending.take 136 = pending := List.take_of_length_le (by omega)
  have dropPending : pending.drop 136 = [] := List.drop_eq_nil_of_le (by omega)
  rw [splitBlocks, if_neg lengthFull, List.take_append, List.drop_append, takePending, dropPending]
  simp

structure StorageUpdate where
  emitted : List Message
  storage : Message
  buffered : Nat

def sourceChunkTail (written : Message) (complete : List Message) (remaining : Message) : StorageUpdate :=
  let (blocks, tail) := splitBlocks remaining
  ⟨complete ++ blocks, overwriteWindow written 0 tail, tail.length⟩

def sourceDriver (storage : Message) (buffered : Nat) (input : Message) : StorageUpdate :=
  if sourceHasPending buffered then
    let copied := sourceCopied input.length buffered
    let written := overwriteWindow storage buffered (input.take copied)
    if sourceStops input.length buffered then
      ⟨[], written, sourceEnd input.length buffered⟩
    else sourceChunkTail written [written] (input.drop copied)
  else sourceChunkTail storage [] input

private theorem overwriteWindow_size (storage input : Message) (offset : Nat)
    (valid : offset + input.length ≤ storage.length) :
    (overwriteWindow storage offset input).length = storage.length := by
  simp only [overwriteWindow, List.length_append, List.length_take, List.length_drop]
  rw [Nat.min_eq_left (by omega : offset ≤ storage.length)]
  omega

theorem sourceCopied_refines (incoming buffered : Nat) :
    sourceCopied incoming buffered = min incoming (136 - buffered) := by
  rfl

private theorem sourceChunkTail_refines (storage remaining : Message) (complete : List Message)
    (width : storage.length = 136) :
    let out := sourceChunkTail storage complete remaining
    out.storage.length = 136 ∧
      (out.emitted, out.storage.take out.buffered) =
        (complete ++ (splitBlocks remaining).1, (splitBlocks remaining).2) := by
  have short := (splitBlocks_partition remaining).short
  have window : 0 + (splitBlocks remaining).2.length ≤ storage.length := by omega
  have copied := overwrittenPrefix storage (splitBlocks remaining).2 0 (by omega)
  simp only [Nat.zero_add, List.take_zero, List.nil_append] at copied
  simp only [sourceChunkTail, overwriteWindow_size _ _ _ window, width, copied, and_self]

theorem sourceDriver_refines (storage input : Message) (buffered : Nat)
    (width : storage.length = 136) (short : buffered < 136) :
    let out := sourceDriver storage buffered input
    out.storage.length = 136 ∧ out.buffered < 136 ∧
      (out.emitted, out.storage.take out.buffered) = splitBlocks (storage.take buffered ++ input) := by
  let pending := storage.take buffered
  have pendingSize : pending.length = buffered := List.length_take_of_le (by omega)
  change (sourceDriver storage buffered input).storage.length = 136 ∧
    (sourceDriver storage buffered input).buffered < 136 ∧
    ((sourceDriver storage buffered input).emitted,
      (sourceDriver storage buffered input).storage.take (sourceDriver storage buffered input).buffered) =
        splitBlocks (pending ++ input)
  by_cases isEmpty : buffered = 0
  · have tail := sourceChunkTail_refines storage input [] width
    have tailShort : (sourceChunkTail storage [] input).buffered < 136 := (splitBlocks_partition input).short
    rw [isEmpty, sourceDriver, if_neg (by decide : ¬ sourceHasPending 0)]
    refine ⟨tail.1, tailShort, ?_⟩
    simpa only [pending, isEmpty, List.take_zero, List.nil_append] using tail.2
  · have active : sourceHasPending buffered := isEmpty
    rw [sourceDriver, if_pos active]
    have stops : sourceStops input.length buffered ↔ input.length < 136 - buffered := by
      unfold sourceStops
      omega
    by_cases small : input.length < 136 - buffered
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
    · let room := 136 - buffered
      have fits : room ≤ input.length := by omega
      have copied : sourceCopied input.length buffered = room := by
        rw [sourceCopied_refines, Nat.min_eq_right fits]
      let written := overwriteWindow storage buffered (input.take room)
      have piece : (input.take room).length = room := List.length_take_of_le fits
      have writtenWidth : written.length = 136 := by
        change (overwriteWindow storage buffered (input.take room)).length = 136
        rw [overwriteWindow_size _ _ _ (by omega), width]
      have writtenEq : written = pending ++ input.take room := by
        have copiedPrefix := overwrittenPrefix storage (input.take room) buffered (by omega)
        have exactly : buffered + (input.take room).length = 136 := by omega
        have takeFull : written.take 136 = written := List.take_of_length_le (by omega)
        rw [exactly] at copiedPrefix
        exact takeFull.symm.trans copiedPrefix
      rw [if_neg (fun stopsHere => small (stops.mp stopsHere)), copied]
      have tail := sourceChunkTail_refines written (input.drop room) [written] writtenWidth
      have tailShort : (sourceChunkTail written [written] (input.drop room)).buffered < 136 :=
        (splitBlocks_partition (input.drop room)).short
      refine ⟨tail.1, tailShort, tail.2.trans ?_⟩
      rw [fill_buffer_full pending input (by omega) (by omega), pendingSize, writtenEq]
      rfl

/-- A decomposition into complete rate blocks and a short tail is unique. -/
theorem Partition.equalsSplit {message pending : Message} {blocks : List Message}
    (partition : Partition message blocks pending) : splitBlocks message = (blocks, pending) := by
  obtain ⟨wire, full, short⟩ := partition
  rw [← wire]
  clear wire message
  induction blocks with
  | nil => simp [splitBlocks, short]
  | cons first rest onward =>
    have width := full first (by simp)
    have restFull : ∀ block ∈ rest, block.length = 136 := by
      intro block member
      exact full block (List.mem_cons_of_mem first member)
    simp only [List.flatten_cons, List.append_assoc]
    have long : ¬ (first ++ (rest.flatten ++ pending)).length < 136 := by simp [width]
    have takeFirst : (first ++ (rest.flatten ++ pending)).take 136 = first := by
      rw [← width, List.take_append_length]
    have dropFirst : (first ++ (rest.flatten ++ pending)).drop 136 = rest.flatten ++ pending := by
      rw [← width, List.drop_left]
    rw [splitBlocks, if_neg long, takeFirst, dropFirst, onward restFull]

def blockOf (bytes : Message) : Block := fun i => bytes[i.val]?.getD 0

theorem paddedRate_eq_of_prefix (used : Nat) (left right : Message)
    (same : left.take used = right.take used) : paddedRate .shake used (blockOf left) = paddedRate .shake used (blockOf right) := by
  funext i
  by_cases live : i.val < used
  · simp only [paddedRate, if_pos live, blockOf]
    have leftAt := List.getElem?_take_of_lt (l := left) live
    have rightAt := List.getElem?_take_of_lt (l := right) live
    rw [← leftAt, same, rightAt]
  · simp [paddedRate, live]

structure Context where
  lanes : State
  storage : Message
  buffered : Nat

def sourceNew : Context := ⟨sourceNewLanes, sourceNewStorage, sourceNewBuffered⟩

def Context.liveBytes (ctx : Context) : Message := ctx.storage.take ctx.buffered

def Context.valid (ctx : Context) : Prop := ctx.storage.length = 136 ∧ ctx.buffered < 136

def sourceUpdate (ctx : Context) (input : Message) : Context :=
  let next := sourceDriver ctx.storage ctx.buffered input
  ⟨(next.emitted.map blockOf).foldl sourceAbsorb ctx.lanes, next.storage, next.buffered⟩

def Represents (ctx : Context) (message : Message) : Prop :=
  ∃ blocks, Partition message blocks ctx.liveBytes ∧ ctx.valid ∧
    ctx.lanes = (blocks.map blockOf).foldl sourceAbsorb (fun _ => 0)

theorem sourceNew_refines : sourceNew.valid ∧ Represents sourceNew [] := by
  have valid : sourceNew.valid := ⟨rfl, by decide⟩
  exact ⟨valid, ⟨[], ⟨rfl, by simp, by decide⟩, valid, rfl⟩⟩

theorem sourceUpdate_preserves (ctx : Context) (msg input : Message) (repr : Represents ctx msg) :
    Represents (sourceUpdate ctx input) (msg ++ input) := by
  obtain ⟨blocks, original, valid, lanes⟩ := repr
  obtain ⟨width, short, split⟩ := sourceDriver_refines ctx.storage input ctx.buffered valid.1 valid.2
  have blockEq := congrArg Prod.fst split
  have tailEq := congrArg Prod.snd split
  dsimp only at blockEq tailEq
  let next := sourceDriver ctx.storage ctx.buffered input
  change ∃ completed, Partition (msg ++ input) completed (next.storage.take next.buffered) ∧
    (next.storage.length = 136 ∧ next.buffered < 136) ∧
    (next.emitted.map blockOf).foldl sourceAbsorb ctx.lanes =
      (completed.map blockOf).foldl sourceAbsorb (fun _ => 0)
  refine ⟨blocks ++ next.emitted, ?_, ⟨width, short⟩, ?_⟩
  · change next.emitted = (splitBlocks (ctx.liveBytes ++ input)).1 at blockEq
    change next.storage.take next.buffered = (splitBlocks (ctx.liveBytes ++ input)).2 at tailEq
    rw [blockEq, tailEq]
    exact original.feed input
  · rw [List.map_append, List.foldl_append, lanes]

theorem sourceUpdateTrace_preserves (ctx : Context) (msg : Message) (chunks : List Message)
    (repr : Represents ctx msg) :
    Represents (chunks.foldl sourceUpdate ctx) (msg ++ chunks.flatten) := by
  induction chunks generalizing ctx msg with
  | nil => simpa using repr
  | cons next rest ih =>
    simpa only [List.foldl_cons, List.flatten_cons, List.append_assoc] using
      ih (sourceUpdate ctx next) (msg ++ next) (sourceUpdate_preserves ctx msg next repr)

private def startCursor : Cursor := ⟨0, 0, by decide⟩

def sourceFinishWith (ctx : Context) (requests : List Nat) : Message :=
  let final := sourceShakeFinalize ctx.lanes ctx.buffered (blockOf ctx.storage)
  let count := (requests.sum + 135) / 136
  (sourceReadTrace (wordByte (sourceOutput count final.1)) startCursor requests).1

def sourceShakeTrace (chunks : List Message) (requests : List Nat) : Message :=
  sourceFinishWith (chunks.foldl sourceUpdate sourceNew) requests

/-- The public Rust `xof` closure calls new, update, finalize, and read in order. -/
def sourceXof (message : Message) (requested : Nat) : Message :=
  sourceFinishWith (sourceUpdate sourceNew message) [requested]

def fipsShakeBits (message : Message) (requested : Nat) (bit : Fin 8) : List Bool :=
  let split := splitBlocks message
  let start := (split.1.map blockOf).foldl bitAbsorb (fun _ _ => false)
  let final := bitAbsorb start (paddedRate .shake split.2.length (blockOf split.2))
  let wire := bitOutput ((requested + 135) / 136) final
  (List.range' 0 requested).map fun position => specBit wire position bit

/-- Streaming input and reading use the same FIPS bit stream for every finite partition. -/
theorem sourceShakeTrace_bits (chunks : List Message) (requests : List Nat) (bit : Fin 8) :
    (sourceShakeTrace chunks requests).map (fun byte => byte.getLsbD bit.val) =
      fipsShakeBits chunks.flatten requests.sum bit := by
  let ctx := chunks.foldl sourceUpdate sourceNew
  have represents : Represents ctx chunks.flatten := by
    simpa only [List.nil_append] using sourceUpdateTrace_preserves sourceNew [] chunks sourceNew_refines.2
  obtain ⟨blocks, partition, shape, lanes⟩ := represents
  have partitionEq := partition.equalsSplit
  have bits : bitsOf ctx.lanes = (blocks.map blockOf).foldl bitAbsorb (fun _ _ => false) := by
    rw [lanes, sourceAbsorb_blocks_bits]
    congr 1
    funext _ _
    simp [bitsOf]
  have lengthEq : ctx.liveBytes.length = ctx.buffered :=
    List.length_take_of_le (by have := shape.1; have := shape.2; omega)
  have tailEq : ctx.storage.take ctx.buffered = ctx.liveBytes.take ctx.buffered := by
    rw [List.take_of_length_le (by omega : ctx.liveBytes.length ≤ ctx.buffered)]
    rfl
  have wire := sourceShakeReadTrace_bits ctx.lanes ctx.buffered shape.2 (blockOf ctx.storage) startCursor requests bit
  have initOffset : startCursor.offset = 0 := rfl
  simp only [initOffset, Nat.zero_add] at wire
  rw [sourceShakeTrace, sourceFinishWith, fipsShakeBits, partitionEq]
  dsimp only [Prod.fst, Prod.snd]
  rw [wire, bits, paddedRate_eq_of_prefix _ _ _ tailEq, lengthEq]

theorem sourceXof_bits (message : Message) (requested : Nat) (bit : Fin 8) :
    (sourceXof message requested).map (fun byte => byte.getLsbD bit.val) = fipsShakeBits message requested bit := by
  simpa [sourceXof, sourceShakeTrace] using sourceShakeTrace_bits [message] [requested] bit

private theorem bytes_eq_of_bits (left right : Message)
    (agree : ∀ bit : Fin 8, left.map (fun b => b.getLsbD bit.val) = right.map (fun b => b.getLsbD bit.val)) :
    left = right := by
  induction left generalizing right with
  | nil =>
    cases right with
    | nil => rfl
    | cons first rest => cases agree 0
  | cons first rest ih =>
    cases right with
    | nil => cases agree 0
    | cons head tail =>
      have pair (bit : Fin 8) : first.getLsbD bit.val = head.getLsbD bit.val ∧
          rest.map (fun b => b.getLsbD bit.val) = tail.map (fun b => b.getLsbD bit.val) :=
        List.cons.inj (agree bit)
      have sameByte : first = head := BitVec.eq_of_getLsbD_eq (fun i within => (pair ⟨i, within⟩).1)
      rw [sameByte, ih tail (fun bit => (pair bit).2)]

theorem sourceShakeTrace_eq_xof (chunks : List Message) (requests : List Nat) :
    sourceShakeTrace chunks requests = sourceXof chunks.flatten requests.sum := by
  apply bytes_eq_of_bits
  intro bit
  rw [sourceShakeTrace_bits, sourceXof_bits]

#print axioms sourceCopied_refines
#print axioms sourceDriver_refines
#print axioms sourceNew_refines
#print axioms sourceUpdate_preserves
#print axioms sourceUpdateTrace_preserves
#print axioms sourceShakeTrace_bits
#print axioms sourceXof_bits
#print axioms sourceShakeTrace_eq_xof

end Abc.Refine.Keccak.AbsorbSource
