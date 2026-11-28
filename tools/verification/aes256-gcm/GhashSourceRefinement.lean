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

theorem source_hash_block_refines (key state word : Block) :
    Ghash.hash_block key state word = some (multiplyMask (state ^^^ word) key) := by
  unfold Ghash.hash_block
  rw [source_multiply_returns_nist, multiplyMask_refines_nist]
  rfl

theorem source_nist_example_footer :
    Ghash.pack_lengths 20#64 60#64 = some 0x00000000000000a000000000000001e0#128 := by
  decide +kernel

theorem source_length_word_refines (aadLength cipherLength : BitVec 64) :
    Ghash.pack_lengths aadLength cipherLength =
      some (packedLength aadLength.toNat cipherLength.toNat) := by
  have widen (value : BitVec 64) : value.zeroExtend 128 = BitVec.ofNat 128 value.toNat := by
    apply BitVec.eq_of_toNat_eq
    simp [BitVec.zeroExtend]
  have a := aadLength.isLt
  have c := cipherLength.isLt
  unfold Ghash.pack_lengths packedLength
  rw [widen aadLength, widen cipherLength]
  have safe : (BitVec.ofNat 128 aadLength.toNat).toNat * (8#128).toNat < 2^128 ∧
      (64#32).toNat < 128 ∧
      (BitVec.ofNat 128 cipherLength.toNat).toNat * (8#128).toNat < 2^128 := by
    simp only [BitVec.toNat_ofNat, Nat.mod_eq_of_lt (show aadLength.toNat < 2^128 by omega),
      Nat.mod_eq_of_lt (show cipherLength.toNat < 2^128 by omega)]
    change aadLength.toNat * 8 < 2^128 ∧ 64 < 128 ∧ cipherLength.toNat * 8 < 2^128
    omega
  rw [if_pos safe]
  simp only [show (64#32).toNat = 64 from rfl, ← BitVec.ofNat_mul,
    Nat.mul_comm aadLength.toNat 8, Nat.mul_comm cipherLength.toNat 8]

theorem source_length_word_matches_nist_bytes (aadLength cipherLength : BitVec 64)
    (aadFits : 8 * aadLength.toNat < 2^64) (cipherFits : 8 * cipherLength.toNat < 2^64) :
    Ghash.pack_lengths aadLength cipherLength =
      some (asBlock (lengthBytes aadLength.toNat cipherLength.toNat)) := by
  rw [source_length_word_refines, packedLength_matches_bytes _ _ aadFits cipherFits]

theorem source_finish_tag_refines (key state lengths mask : Block) :
    Ghash.finish_tag key state lengths mask = some (multiplyMask (state ^^^ lengths) key ^^^ mask) := by
  unfold Ghash.finish_tag
  rw [source_hash_block_refines]
  rfl

def hashWords (key : Block) (state : Block) : List Block → Option Block
  | [] => some state
  | word :: words => do
    let next ← Ghash.hash_block key state word
    hashWords key next words

theorem source_hash_words_refines (key state : Block) (words : List Block) :
    hashWords key state words = some (words.foldl (fun acc word => multiplyMask (acc ^^^ word) key) state) := by
  induction words generalizing state with
  | nil => rfl
  | cons word words ih =>
    simp only [hashWords, source_hash_block_refines, List.foldl_cons, bind, Option.bind_some, ih]

-- The byte-to-block bridge is the already verified source-shaped chunking and padding model.
def sourceTagWord (key mask : Block) (aad ciphertext : List Byte) : Option Block := do
  let aadState ← hashWords key 0 (sourceBlocks aad)
  let cipherState ← hashWords key aadState (sourceBlocks ciphertext)
  let lengths ← Ghash.pack_lengths (BitVec.ofNat 64 aad.length) (BitVec.ofNat 64 ciphertext.length)
  Ghash.finish_tag key cipherState lengths mask

theorem source_tag_word_refines_nist (key mask : Block) (aad ciphertext : List Byte)
    (aadFits : 8 * aad.length < 2^64) (cipherFits : 8 * ciphertext.length < 2^64) :
    sourceTagWord key mask aad ciphertext = some (ghash key (transcript aad ciphertext) ^^^ mask) := by
  have lengthValue (n : Nat) (fits : 8 * n < 2^64) : (BitVec.ofNat 64 n).toNat = n := by
    rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]
  simp only [sourceTagWord, source_hash_words_refines, bind, Option.bind_some, source_length_word_refines,
    lengthValue _ aadFits, lengthValue _ cipherFits, source_finish_tag_refines]
  change some (ghashSource key aad ciphertext ^^^ mask) = _
  rw [ghashSource_refines_nist _ _ _ aadFits cipherFits]

theorem source_tag_bytes_under_aes_contract (encrypt : Block → Block) (nonce : Nonce)
    (aad ciphertext : List Byte) (aadFits : 8 * aad.length < 2^64) (cipherFits : 8 * ciphertext.length < 2^64) :
    (sourceTagWord (encrypt 0) (encrypt (counterBlock nonce 1)) aad ciphertext).map asTag =
      some (authenticate encrypt nonce aad ciphertext) := by
  rw [source_tag_word_refines_nist _ _ _ _ aadFits cipherFits]
  rfl

#print axioms extracted_round_refines
#print axioms extracted_loop_refines
#print axioms source_multiply_returns_nist
#print axioms source_hash_block_refines
#print axioms source_nist_example_footer
#print axioms source_length_word_refines
#print axioms source_length_word_matches_nist_bytes
#print axioms source_finish_tag_refines
#print axioms source_hash_words_refines
#print axioms source_tag_word_refines_nist
#print axioms source_tag_bytes_under_aes_contract

end Abc.Refine.Ghash
