import KeccakReaderLlbc

namespace Abc.Refine.Keccak.ReaderSource

open Abc.Spec.KeccakRound
open Abc.Spec.Keccak.Reader (Cursor ready spanCount after span span_progress read_correct readTrace read_trace_correct)
open Abc.Spec.Keccak.SpongeRead (wordByte word_byte_bits specBit)
open Abc.Refine.Keccak.Source
open Abc.Refine.Keccak.WrapperSource

theorem sourceReadRefresh_refines (offset : Nat) : sourceReadRefresh offset ↔ offset = 136 := by
  rfl

def sourceReady (cursor : Cursor) : Cursor :=
  if sourceReadRefresh cursor.within then ⟨cursor.block + 1, sourceReadReset, by decide⟩ else cursor

theorem sourceReady_refines (cursor : Cursor) : sourceReady cursor = ready cursor := by
  rfl

theorem sourceReadCount_refines (cursor : Cursor) (remaining : Nat) :
    sourceReadCount remaining (sourceReady cursor).within = spanCount cursor remaining := by
  rw [sourceReady_refines]
  exact Nat.min_comm _ _

theorem sourceReadRange_refines (cursor : Cursor) (remaining : Nat) :
    let pos := (sourceReady cursor).within
    sourceReadStart remaining pos = (ready cursor).within ∧
      sourceReadEnd remaining pos = (ready cursor).within + spanCount cursor remaining ∧
      sourceReadNext remaining pos = sourceReadEnd remaining pos := by
  dsimp only
  rw [← sourceReady_refines, ← sourceReadCount_refines]
  exact ⟨rfl, rfl, rfl⟩

def sourceAfter (cursor : Cursor) (remaining : Nat) : Cursor :=
  ⟨(sourceReady cursor).block, sourceReadNext remaining (sourceReady cursor).within, by
    rw [(sourceReadRange_refines cursor remaining).2.2, (sourceReadRange_refines cursor remaining).2.1]
    exact (after cursor remaining).withinRate⟩

theorem sourceAfter_refines (cursor : Cursor) (remaining : Nat) :
    sourceAfter cursor remaining = after cursor remaining := by
  have step := (sourceReadRange_refines cursor remaining).2
  rw [sourceReady_refines] at step
  simp only [sourceAfter, after, sourceReady_refines, step.2, step.1]

def sourceSpan (source : Nat → Byte) (cursor : Cursor) (remaining : Nat) : List Byte :=
  let prepared := sourceReady cursor
  (List.range' (sourceReadStart remaining prepared.within) (sourceReadCount remaining prepared.within)).map
    (fun i => source (136 * prepared.block + i))

theorem sourceSpan_refines (source : Nat → Byte) (cursor : Cursor) (remaining : Nat) :
    sourceSpan source cursor remaining = span source cursor remaining := by
  unfold sourceSpan span
  dsimp only
  rw [sourceReadCount_refines, (sourceReadRange_refines cursor remaining).1, sourceReady_refines]

def sourceRead (source : Nat → Byte) (cursor : Cursor) (remaining : Nat) : List Byte × Cursor :=
  if _empty : sourceReadEmpty remaining then ([], cursor)
  else
    let count := sourceReadCount remaining (sourceReady cursor).within
    let next := sourceRead source (sourceAfter cursor remaining) (remaining - count)
    (sourceSpan source cursor remaining ++ next.1, next.2)
termination_by remaining
decreasing_by
  rw [sourceReadCount_refines]
  have positive : 0 < remaining := by unfold sourceReadEmpty at _empty; omega
  have := span_progress cursor positive
  omega

theorem sourceRead_refines (source : Nat → Byte) (cursor : Cursor) (remaining : Nat) :
    sourceRead source cursor remaining = Abc.Spec.Keccak.Reader.read source cursor remaining := by
  rw [sourceRead, Abc.Spec.Keccak.Reader.read]
  by_cases empty : remaining = 0
  · simp [sourceReadEmpty, empty]
  · have progress := span_progress cursor (Nat.pos_of_ne_zero empty)
    have notSource : ¬ sourceReadEmpty remaining := empty
    simp only [dif_neg notSource, dif_neg empty, sourceReadCount_refines, sourceAfter_refines, sourceSpan_refines]
    rw [sourceRead_refines source (after cursor remaining) (remaining - spanCount cursor remaining)]
termination_by remaining

theorem sourceShakeRead_bits (state : State) (used : Nat) (within : used < 136)
    (tail : Block) (cursor : Cursor) (requested : Nat) (z : Fin 8) :
    let count := (cursor.offset + requested + 135) / 136
    let finalized := sourceShakeFinalize state used tail
    let words := sourceOutput count finalized.1
    let bits := bitOutput count (bitAbsorb (bitsOf state) (paddedRate .shake used tail))
    ((sourceRead (wordByte words) cursor requested).1.map (fun byte => byte.getLsbD z.val)) =
      (List.range' cursor.offset requested).map (fun position => specBit bits position z) := by
  dsimp only
  rw [sourceRead_refines, (read_correct _ cursor requested).1, List.map_map]
  apply List.map_congr_left
  intro position _
  rw [Function.comp_apply, word_byte_bits, sourceOutput_blocks_bits,
    (sourceShakeFinalize_bits state used within tail).1]

def sourceReadTrace (source : Nat → Byte) (cursor : Cursor) : List Nat → List Byte × Cursor
  | [] => ([], cursor)
  | requested :: rest =>
    let first := sourceRead source cursor requested
    let later := sourceReadTrace source first.2 rest
    (first.1 ++ later.1, later.2)

theorem sourceReadTrace_refines (source : Nat → Byte) (cursor : Cursor) (requests : List Nat) :
    sourceReadTrace source cursor requests = readTrace source cursor requests := by
  induction requests generalizing cursor with
  | nil => rfl
  | cons requested rest ih =>
    simp only [sourceReadTrace, readTrace, sourceRead_refines, ih]

theorem sourceShakeReadTrace_bits (state : State) (used : Nat) (within : used < 136)
    (tail : Block) (cursor : Cursor) (requests : List Nat) (z : Fin 8) :
    let count := (cursor.offset + requests.sum + 135) / 136
    let finalized := sourceShakeFinalize state used tail
    let words := sourceOutput count finalized.1
    let bits := bitOutput count (bitAbsorb (bitsOf state) (paddedRate .shake used tail))
    ((sourceReadTrace (wordByte words) cursor requests).1.map (fun byte => byte.getLsbD z.val)) =
      (List.range' cursor.offset requests.sum).map (fun position => specBit bits position z) := by
  dsimp only
  rw [sourceReadTrace_refines, (read_trace_correct _ cursor requests).1, ← sourceRead_refines]
  exact sourceShakeRead_bits state used within tail cursor requests.sum z

#print axioms sourceReadRefresh_refines
#print axioms sourceReady_refines
#print axioms sourceReadCount_refines
#print axioms sourceReadRange_refines
#print axioms sourceAfter_refines
#print axioms sourceSpan_refines
#print axioms sourceRead_refines
#print axioms sourceShakeRead_bits
#print axioms sourceReadTrace_refines
#print axioms sourceShakeReadTrace_bits

end Abc.Refine.Keccak.ReaderSource
