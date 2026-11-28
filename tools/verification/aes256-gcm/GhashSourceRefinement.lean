import Aes256GcmComposition
import GhashLlbc

namespace Abc.Refine.Ghash

open Abc.Spec.Aes256Gcm.Composition
open Abc.Extracted

private theorem counter_word_value (n : Nat) (bound : n ≤ 128) :
    (BitVec.ofNat 32 n).toNat = n := by
  rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]

private theorem decrement_remaining (remaining : Nat) (bound : remaining < 128) :
    BitVec.ofNat 32 (remaining + 1) - 1#32 = BitVec.ofNat 32 remaining := by
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.toNat_sub, counter_word_value (remaining + 1) (by omega),
    counter_word_value remaining (by omega)]
  change (2^32 - 1 + (remaining + 1)) % 2^32 = remaining
  omega

theorem extracted_round_refines (input product key : Block) (remaining : Nat) (bound : remaining < 128) :
    Ghash.step input (BitVec.ofNat 32 (remaining + 1)) product key =
      some (BitVec.ofNat 32 remaining, maskMultiplyStep input remaining (product, key)) := by
  have dec := decrement_remaining remaining bound
  have later := counter_word_value remaining (by omega)
  have earlier := counter_word_value (remaining + 1) (by omega)
  simp only [Ghash.step, dec, later, earlier]
  have safe : (1#32).toNat ≤ remaining + 1 ∧ remaining < 128 ∧ (1#32).toNat < 128 := by
    change 1 ≤ remaining + 1 ∧ remaining < 128 ∧ 1 < 128
    omega
  rw [if_pos safe]
  rfl

private theorem continues_nonzero (input product key : Block) (remaining : Nat) (bound : remaining < 128) :
    Ghash.continues input (BitVec.ofNat 32 (remaining + 1)) product key = true := by
  unfold Ghash.continues
  apply bne_iff_ne.mpr
  intro equal
  have value := congrArg BitVec.toNat equal
  rw [counter_word_value (remaining + 1) (by omega)] at value
  change remaining + 1 = 0 at value
  omega

theorem extracted_loop_refines (input : Block) (remaining : Nat) (state : ProductState)
    (bound : remaining ≤ 128) :
    Ghash.run input remaining (BitVec.ofNat 32 remaining, state) =
      some (descendingLoop (maskMultiplyStep input) remaining state).1 := by
  induction remaining generalizing state with
  | zero =>
    obtain ⟨product, key⟩ := state
    rfl
  | succ remaining ih =>
    obtain ⟨product, key⟩ := state
    rw [Ghash.run, continues_nonzero _ _ _ _ (by omega),
      extracted_round_refines _ _ _ _ (by omega), descendingLoop]
    exact ih _ (by omega)

theorem source_multiply_returns_nist (input key : Block) :
    Ghash.multiply input key = some (multiply input key) := by
  have calculated := extracted_loop_refines input 128 (0, key) (by decide)
  change Ghash.multiply input key = some (multiplyMask input key) at calculated
  rw [calculated, multiplyMask_refines_nist]

#print axioms extracted_round_refines
#print axioms extracted_loop_refines
#print axioms source_multiply_returns_nist

end Abc.Refine.Ghash
