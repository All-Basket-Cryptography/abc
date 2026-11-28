import ScryptBounds
import ScryptSalsaSource
import Std.Tactic.BVDecide

namespace Abc.Refine.Scrypt.Source

open Abc.Spec.Scrypt Abc.Spec.Scrypt.Functional

private theorem pack_xor (first second : Chunk) :
    packWords (xorChunk first second) = fun i => packWords first i ^^^ packWords second i := by
  funext i
  simp only [packWords, xorChunk, ← BitVec.xor_append]

private theorem pack_unpack (words : WordState) : packWords (unpackWords words) = words := by
  funext i
  have byte (j : Fin 4) :
      unpackWords words ⟨4 * i.val + j.val, by omega⟩ = (words i).extractLsb' (8 * j.val) 8 := by
    have quotient : (4 * i.val + j.val) / 4 = i.val := by omega
    have remainder : (4 * i.val + j.val) % 4 = j.val := by omega
    simp only [unpackWords, quotient, remainder]
  simp only [packWords, byte]
  change ((((words i).extractLsb' 24 8 ++ (words i).extractLsb' 16 8) ++
    (words i).extractLsb' 8 8) ++ (words i).extractLsb' 0 8) = words i
  generalize words i = word
  bv_decide

private def CheckFin : (n : Nat) → (Fin n → Prop) → Prop
  | 0, _ => True
  | n + 1, p => p 0 ∧ CheckFin n (fun i => p i.succ)

private theorem checkFin {n : Nat} {p : Fin n → Prop} (h : CheckFin n p) : ∀ i, p i := by
  induction n with
  | zero => intro i; exact Fin.elim0 i
  | succ n ih => exact Fin.cases h.1 (ih h.2)

theorem sourceBlockMixSeed_refines (last : Chunk) : sourceBlockMixSeed last = packWords last := by
  funext i
  refine checkFin (p := fun j => sourceBlockMixSeed last j = packWords last j) ?_ i
  simp only [CheckFin]
  repeat' first | apply And.intro | rfl | exact True.intro

theorem sourceBlockMixInput_refines (previous : WordState) (block : Chunk) :
    sourceBlockMixInput previous block = fun i => previous i ^^^ packWords block i := by
  funext i
  refine checkFin (p := fun j => sourceBlockMixInput previous block j = previous j ^^^ packWords block j) ?_ i
  simp only [CheckFin]
  repeat' first | apply And.intro | rfl | exact True.intro

theorem sourceBlockMixSerialize_refines (words : WordState) : sourceBlockMixSerialize words = unpackWords words := by
  funext i
  refine checkFin (p := fun j => sourceBlockMixSerialize words j = unpackWords words j) ?_ i
  simp only [CheckFin]
  repeat' first | apply And.intro | rfl | exact True.intro

/-- Apply the extracted per-block body in the order supplied by `chunks_exact`. -/
def sourceBlockMixWordTrace : WordState → List Chunk → List WordState
  | _, [] => []
  | previous, input :: tail =>
    let next := sourceSalsa8 (sourceBlockMixInput previous input)
    next :: sourceBlockMixWordTrace next tail

/-- The extracted inner loads, XOR, actual Salsa20/8 and all output bytes
agree with every iteration of the RFC's chain, for any number of blocks. -/
theorem sourceBlockMixWordTrace_refines (initial : Chunk) (inputs : List Chunk) :
    (sourceBlockMixWordTrace (packWords initial) inputs).map sourceBlockMixSerialize =
      salsaChain rfcSalsaBytes initial inputs := by
  induction inputs generalizing initial with
  | nil => rfl
  | cons block tail ih =>
    let next := rfcSalsaBytes (xorChunk initial block)
    have words : sourceSalsa8 (sourceBlockMixInput (packWords initial) block) = packWords next := by
      unfold next rfcSalsaBytes
      rw [pack_unpack, sourceBlockMixInput_refines, sourceSalsa8_refines, pack_xor]
    have encoded : sourceBlockMixSerialize (packWords next) = next := by
      rw [← words, sourceBlockMixSerialize_refines, sourceBlockMixInput_refines, sourceSalsa8_refines, ← pack_xor]
      rfl
    simp only [sourceBlockMixWordTrace, salsaChain, List.map_cons, words, encoded, ih next, next]

/-- Each extracted loop index selects the RFC's destination and writes
one whole block within an admissible lane. -/
theorem sourceBlockMixTraversal_refines (r index : Nat) (positive : 0 < r) (indexFits : index < 2 * r) :
    sourceBlockMixCount (128 * r) = 2 * r ∧
    sourceBlockMixSeedOffset (128 * r) = (2 * r - 1) * 64 ∧
    sourceBlockMixOffset (128 * r) index = destination r index * 64 ∧
    sourceBlockMixOffset (128 * r) index + 64 ≤ 128 * r := by
  have count : 128 * r / 64 = 2 * r := by omega
  have half : 2 * r / 2 = r := by omega
  have route := destination_in_range r index indexFits
  have offset : sourceBlockMixOffset (128 * r) index = destination r index * 64 := by
    rw [sourceBlockMixOffset, count, half, destination]
  refine ⟨count, ?_, offset, ?_⟩
  · unfold sourceBlockMixSeedOffset
    omega
  · rw [offset]
    omega

private def laneBlock (lane : Bytes) (offset : Nat) : Chunk :=
  fun i => lane[offset + i.val]?.getD 0

private def laneBlocks (lane : Bytes) (count : Nat) : List Chunk :=
  (List.range count).map (fun i => laneBlock lane (i * 64))

/-- Ordered blocks emitted by the extracted traversal before they are scattered. -/
def sourceBlockMixBlocks (lane : Bytes) : List Chunk :=
  let last := laneBlock lane (sourceBlockMixSeedOffset lane.length)
  (sourceBlockMixWordTrace (sourceBlockMixSeed last)
    (laneBlocks lane (sourceBlockMixCount lane.length))).map sourceBlockMixSerialize

theorem sourceBlockMixBlocks_refines (lane : Bytes) (r : Nat) (positive : 0 < r) (size : lane.length = 128 * r) :
    sourceBlockMixBlocks lane =
      salsaChain rfcSalsaBytes ((laneBlocks lane (2 * r)).getLastD fun _ => 0) (laneBlocks lane (2 * r)) := by
  obtain ⟨count, offset, _, _⟩ := sourceBlockMixTraversal_refines r 0 positive (by omega)
  have lastRange : List.range (2 * r) = List.range (2 * r - 1) ++ [2 * r - 1] := by
    have length : (2 * r - 1).succ = 2 * r := by omega
    simpa only [length] using (List.range_succ (n := 2 * r - 1))
  have last : (laneBlocks lane (2 * r)).getLastD (fun _ => 0) = laneBlock lane ((2 * r - 1) * 64) := by
    rw [laneBlocks, lastRange, List.map_append, List.map_singleton, List.getLastD_concat]
  unfold sourceBlockMixBlocks
  dsimp only
  rw [sourceBlockMixSeed_refines, sourceBlockMixWordTrace_refines, size, count, offset, last]

/-- Each output slot has a unique source write, and no block is discarded. -/
theorem sourceBlockMixScatter_refines (r slot : Nat) (positive : 0 < r) (fits : slot < 2 * r) :
    originalIndex r slot < 2 * r ∧
    sourceBlockMixOffset (128 * r) (originalIndex r slot) = slot * 64 ∧
    (∀ i < 2 * r, sourceBlockMixOffset (128 * r) i = slot * 64 → i = originalIndex r slot) := by
  have within : originalIndex r slot < 2 * r := by unfold originalIndex; split <;> omega
  have located := (sourceBlockMixTraversal_refines r _ positive within).2.2.1
  refine ⟨within, ?_, ?_⟩
  · rw [located, scatter_has_right_inverse]
  · intro i iFits equal
    have computed := (sourceBlockMixTraversal_refines r i positive iFits).2.2.1
    have eq : destination r i = slot := by rw [computed] at equal; omega
    rw [← eq, scatter_has_left_inverse r i iFits]

/-- Read the source writes in increasing destination order. The inverse is
justified by `sourceBlockMixScatter_refines` and never reads an old slot. -/
def sourceBlockMixBytes (r : Nat) (lane : Bytes) : Bytes :=
  let outputs := sourceBlockMixBlocks lane
  ((List.range (sourceBlockMixCount lane.length)).map
    (fun slot => outputs[originalIndex r slot]?.getD fun _ => 0)).flatMap List.ofFn

theorem sourceBlockMixBytes_refines (r : Nat) (lane : Bytes) (positive : 0 < r) (size : lane.length = 128 * r) :
    sourceBlockMixBytes r lane = blockMix rfcSalsaBytes r lane := by
  obtain ⟨count, _, _, _⟩ := sourceBlockMixTraversal_refines r 0 positive (by omega)
  have rangeSplit : List.range (2 * r) = List.range r ++ (List.range r).map (r + ·) := by
    rw [show 2 * r = r + r by omega, List.range_add]
  unfold sourceBlockMixBytes
  rw [sourceBlockMixBlocks_refines lane r positive size, size, count]
  let outputs := salsaChain rfcSalsaBytes ((laneBlocks lane (2 * r)).getLastD fun _ => 0) (laneBlocks lane (2 * r))
  change ((List.range (2 * r)).map
    (fun slot => outputs[originalIndex r slot]?.getD fun _ => 0)).flatMap List.ofFn =
    (((List.range r).map (fun slot => outputs[2 * slot]?.getD fun _ => 0)) ++
     ((List.range r).map (fun slot => outputs[2 * slot + 1]?.getD fun _ => 0))).flatMap List.ofFn
  apply congrArg (fun (blocks : List Chunk) => blocks.flatMap (fun chunk => List.ofFn chunk))
  rw [rangeSplit, List.map_append, List.map_map]
  congr 1
  · apply List.map_congr_left
    intro slot mem
    simp only [originalIndex, if_pos (List.mem_range.mp mem)]
  · apply List.map_congr_left
    intro slot _
    have odd : originalIndex r (r + slot) = 2 * slot + 1 := by
      unfold originalIndex
      rw [if_neg (by omega : ¬r + slot < r)]
      omega
    simp only [Function.comp_apply, odd]

#print axioms sourceBlockMixSeed_refines
#print axioms sourceBlockMixInput_refines
#print axioms sourceBlockMixSerialize_refines
#print axioms sourceBlockMixWordTrace_refines
#print axioms sourceBlockMixTraversal_refines
#print axioms sourceBlockMixBlocks_refines
#print axioms sourceBlockMixScatter_refines
#print axioms sourceBlockMixBytes_refines

end Abc.Refine.Scrypt.Source
