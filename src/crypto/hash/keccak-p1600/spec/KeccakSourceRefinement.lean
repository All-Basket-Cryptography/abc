import KeccakLlbc

namespace Abc.Refine.Keccak.Source

open Abc.Spec.KeccakRound

set_option maxRecDepth 4096 in
theorem sourceConstants_refine : ∀ round : RoundIndex, sourceConstants round = iotaFormula round := by
  decide

set_option maxRecDepth 4096 in
theorem sourceRound_refines (state : State) (constant : Lane) :
    sourceRound state constant = addIota (chi (rhoPi (theta state) piInverse rhoFormula)) constant := by
  apply funext
  simp only [Fin.forall_fin_succ, Fin.forall_fin_zero]
  repeat' apply And.intro
  all_goals first | rfl | exact True.intro

theorem sourcePermutation_refines (state : State) :
    sourcePermutation state = runRounds referenceRound (List.finRange 24) state := by
  have same : (fun lanes round => sourceRound lanes (sourceConstants round)) = referenceRound := by
    funext lanes round
    rw [sourceRound_refines, sourceConstants_refine]
    rfl
  rw [sourcePermutation, same, runRounds]

theorem sourcePermutation_bits (state : State) :
    bitsOf (sourcePermutation state) = bitPermutation (bitsOf state) := by
  rw [sourcePermutation_refines, ← permutation_matches]
  exact permutation_bits state

set_option maxRecDepth 4096 in
theorem sourceAbsorbMix_refines (state : State) (block : Block) :
    sourceAbsorbMix state block = absorbBytes state block := by
  apply funext
  simp only [Fin.forall_fin_succ, Fin.forall_fin_zero]
  repeat' apply And.intro
  all_goals first | rfl | exact True.intro

theorem sourceAbsorb_bits (state : State) (block : Block) :
    bitsOf (sourceAbsorb state block) = bitAbsorb (bitsOf state) block := by
  rw [sourceAbsorb, sourceAbsorbMix_refines, sourcePermutation_bits, absorb_rate_lifts, bitAbsorb]

theorem sourceAbsorb_blocks_bits (blocks : List Block) (state : State) :
    bitsOf (blocks.foldl sourceAbsorb state) = blocks.foldl bitAbsorb (bitsOf state) := by
  induction blocks generalizing state with
  | nil => rfl
  | cons block later ih => simp only [List.foldl_cons, ih, sourceAbsorb_bits]

def sourceOutput : Nat → State → List Block
  | 0, _ => []
  | n + 1, state => wordRate state :: sourceOutput n (sourcePermutation state)

theorem sourceOutput_blocks_bits (count : Nat) (state : State) :
    (sourceOutput count state).map blockBits = bitOutput count (bitsOf state) := by
  induction count generalizing state with
  | zero => rfl
  | succ n ih =>
    simp only [sourceOutput, bitOutput, List.map_cons, output_rate_lifts, ih, sourcePermutation_bits]

theorem sourceSponge_blocks_bits (domain : Domain) (used : Nat) (within : used < 136)
    (blocks : List Block) (tail : Block) (state : State) (count : Nat) :
    (sourceOutput count (sourceAbsorb (blocks.foldl sourceAbsorb state)
      (paddingWrites domain used tail))).map blockBits =
    bitOutput count (bitAbsorb (blocks.foldl bitAbsorb (bitsOf state))
      (paddedRate domain used tail)) := by
  rw [sourceOutput_blocks_bits, sourceAbsorb_bits, sourceAbsorb_blocks_bits,
    padding_writes_match domain used within]

#print axioms sourceConstants_refine
#print axioms sourceRound_refines
#print axioms sourcePermutation_refines
#print axioms sourcePermutation_bits
#print axioms sourceAbsorbMix_refines
#print axioms sourceAbsorb_bits
#print axioms sourceAbsorb_blocks_bits
#print axioms sourceOutput_blocks_bits
#print axioms sourceSponge_blocks_bits

end Abc.Refine.Keccak.Source
