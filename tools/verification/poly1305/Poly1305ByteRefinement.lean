import Poly1305EncodingRefinement
import Poly1305SourceRefinement
import Abc.Foundation.Encoding

namespace Abc.Refine.Poly1305.Bytes

open Aeneas Aeneas.Std
open Aeneas.Std.Result
open Abc.Poly1305.Extracted
open Abc.Refine.Poly1305 (columns cachedMultiples source_absorb_polynomial_step)
open Abc.Spec.Poly1305.Go (Columns base bounded live value modulus polynomialStep)

private abbrev Words := Aeneas.Std.Array U64 5#usize
private abbrev Multiples := Aeneas.Std.Array U64 4#usize

private theorem words_length (words : Words) : words.val.length = 5 := by
  have h := words.property
  simpa only [show (5#usize).val = 5 by decide] using h

/-- The reconstruction interprets the five little-endian radix-2^26 digits. -/
def decodedColumns (n : Nat) : Columns :=
  ⟨n % base, n / base % base, n / base^2 % base, n / base^3 % base, n / base^4⟩

private theorem word_read (words : Words) (i : Nat) (bound : i < 5) :
    (words.val.map (fun word => word.val))[i]! = words.val[i]!.val := by
  have inside : i < words.val.length := (words_length words).symm ▸ bound
  have mapped : i < (words.val.map (fun word => word.val)).length := by simpa using inside
  rw [getElem!_pos (words.val.map (fun word => word.val)) i mapped,
    getElem!_pos words.val i inside, List.getElem_map]

private theorem word_lt (word : U128) : word.val < 2^128 := by scalar_tac

private theorem top_lt (n : Nat) (bound : n < 2^128) : n / base^4 < 2^24 := by
  simp only [base]
  omega

theorem source_limbs_columns (word : U128) :
    limbs word ⦃ out => columns out = decodedColumns word.val ⦄ := by
  refine WP.spec_mono (Encoding.source_limbs_refines word) ?_
  intro out exactDigits
  have digit (i : Nat) (bound : i < 5) : out.val[i]!.val = word.val / 2^(26*i) % base := by
    have selected := congrArg (fun list : List Nat => list[i]!) exactDigits
    rw [word_read _ _ bound] at selected
    have right : i < ((List.range 5).map (fun j => word.val / 2^(26*j) % 2^26)).length := by simpa using bound
    simpa only [getElem!_pos ((List.range 5).map (fun j => word.val / 2^(26*j) % 2^26)) i right,
      List.getElem_map, List.getElem_range, base] using selected
  simp only [decodedColumns, columns, digit 0 (by decide), digit 1 (by decide), digit 2 (by decide),
    digit 3 (by decide), digit 4 (by decide), show 26*0 = 0 by decide, Nat.pow_zero, Nat.div_one,
    show 2^(26*1) = base by decide, show 2^(26*2) = base^2 by decide,
    show 2^(26*3) = base^3 by decide, show 2^(26*4) = base^4 by decide,
    Nat.mod_eq_of_lt (show word.val / base^4 < base from Nat.lt_trans (top_lt _ (word_lt word)) (by decide))]

private theorem fixed_index4 (words : Words) : words.index_usize 4#usize = .ok words.val[4]! := by
  simp [Aeneas.Std.Array.index_usize, Aeneas.Std.Array.getElem?_Usize_eq,
    show (4#usize).val = 4 by decide]

private theorem fixed_set (words : Words) (new : U64) :
    columns (words.set 4#usize new) = { columns words with c4 := new.val } := by
  have nth (i : Nat) (hi : i < 5) :
      ((words.set 4#usize new).val)[i]! = if i = 4 then new else words.val[i]! := by
    have original : i < words.val.length := (words_length words).symm ▸ hi
    have updated : i < (words.val.set 4 new).length := by simpa using original
    simp only [Aeneas.Std.Array.set_val_eq, show (4#usize).val = 4 by decide,
      getElem!_pos (words.val.set 4 new) i updated, getElem!_pos words.val i original, List.getElem_set]
    by_cases same : i = 4
    · subst i
      rfl
    · simp only [same, Ne.symm same, if_false]
  simp (disch := decide) only [columns, nth, ↓reduceIte, show 0 ≠ 4 by decide,
    show 1 ≠ 4 by decide, show 2 ≠ 4 by decide, show 3 ≠ 4 by decide]

private theorem decoded_bounded (n bit : Nat) (wordBound : n < 2^128) (bitBound : bit ≤ 2^24) :
    bounded { decodedColumns n with c4 := n / base^4 + bit } base := by
  have top := top_lt n wordBound
  refine ⟨Nat.mod_lt _ (by decide), Nat.mod_lt _ (by decide), Nat.mod_lt _ (by decide),
    Nat.mod_lt _ (by decide), ?_⟩
  simp only [base] at top ⊢
  omega

private theorem decoded_value (n bit : Nat) :
    value { decodedColumns n with c4 := n / base^4 + bit } = n + base^4 * bit := by
  simp [value, decodedColumns, base]
  omega

private theorem encoded_high_limb (word : U64) (bit : U64) (wordBound : word.val < 2^24)
    (high : bit = 0#u64 ∨ bit = 16777216#u64) : (word ||| bit).val = word.val + bit.val := by
  change (word.bv ||| bit.bv).toNat = _
  rw [BitVec.toNat_or]
  rcases high with h | h
  · rw [h]
    change word.val ||| 0 = word.val + 0
    simp
  · rw [h]
    change word.val ||| 2^24 = word.val + 2^24
    rw [Nat.or_comm, Nat.add_comm]
    simpa only [Nat.mul_one] using (Nat.two_pow_add_eq_or_of_lt wordBound 1).symm

private abbrev Bytes16 := Aeneas.Std.Array U8 16#usize

def blockValue (block : Bytes16) : Nat :=
  Abc.Foundation.decodeLittleEndian (block.val.map U8.bv)

private theorem decode_bytes (bytes : List (BitVec 8)) :
    (BitVec.fromLEBytes bytes).toNat = Abc.Foundation.decodeLittleEndian bytes := by
  induction bytes with
  | nil => rfl
  | cons byte tail ih =>
    let rest := BitVec.fromLEBytes tail
    change ((byte.setWidth (8 * tail.length + 8)) |||
      (rest.setWidth (8 * tail.length + 8) <<< (8 : Nat))).toNat = _
    have shiftBound : rest.toNat <<< 8 < 2 ^ (8 * tail.length + 8) := by
      rw [Nat.shiftLeft_eq, Nat.pow_add]
      exact Nat.mul_lt_mul_of_pos_right rest.isLt (by decide)
    rw [BitVec.toNat_or, BitVec.toNat_setWidth_of_le (by omega), BitVec.toNat_shiftLeft,
      BitVec.toNat_setWidth_of_le (by omega), Nat.mod_eq_of_lt shiftBound, Nat.or_comm,
      ← Nat.shiftLeft_add_eq_or_of_lt byte.isLt, Nat.shiftLeft_eq]
    simp only [Abc.Foundation.decodeLittleEndian, Abc.Foundation.decodeBigEndian, List.reverse_cons,
      List.foldl_append, List.foldl_cons, List.foldl_nil]
    rw [show rest.toNat = Abc.Foundation.decodeLittleEndian tail from ih]
    simp only [Abc.Foundation.decodeLittleEndian, Abc.Foundation.decodeBigEndian]
    omega

/-- Exact loading used by the message blocks and the pad half of the key. -/
theorem source_load_block_refines (block : Bytes16) :
    load_block block ⦃ word => word.val = Abc.Foundation.decodeLittleEndian (block.val.map U8.bv) ⦄ := by
  simp only [load_block, WP.spec_ok]
  have width : 8 * (block.val.map U8.bv).length = UScalarTy.U128.numBits := by simp
  change ((BitVec.fromLEBytes (block.val.map U8.bv)).cast width).toNat = _
  rw [BitVec.toNat_cast, decode_bytes]

/-- The exact lower-half key decoder applies the RFC clamp mask and emits
bounded radix limbs for the multiplication cache. -/
theorem source_clamped_key_refines (block : Bytes16) :
    clamped_key block ⦃ out => bounded (columns out) base ∧
      value (columns out) = (blockValue block &&& 0x0ffffffc0ffffffc0ffffffc0fffffff) ⦄ := by
  unfold clamped_key
  step with (source_load_block_refines block) as ⟨word, loaded⟩
  simp only [lift, Aeneas.Std.bind_tc_ok]
  let masked := word &&& 21267647620597763993911028882763415551#u128
  step with (source_limbs_columns masked) as ⟨out, keyEq⟩
  have maskedEq : masked.val = blockValue block &&& 0x0ffffffc0ffffffc0ffffffc0fffffff := by
    change (word.bv &&& 21267647620597763993911028882763415551#128).toNat = _
    rw [BitVec.toNat_and]
    exact congrArg (fun n : Nat => n &&& 0x0ffffffc0ffffffc0ffffffc0fffffff) loaded
  have bound := decoded_bounded masked.val 0 (word_lt masked) (by decide)
  have reconstructed := decoded_value masked.val 0
  simp only [Nat.add_zero, Nat.mul_zero] at bound reconstructed
  rw [keyEq, ← maskedEq]
  exact ⟨bound, reconstructed⟩

/-- The exact encoded-block helper adds the RFC stop bit at bit 128 when
handling a full block. The final padded block uses zero as the extra bit. -/
theorem source_absorb_encoded_refines (h r : Words) (rFive : Multiples) (word : U128) (bit : U64)
    (state : live (columns h)) (key : bounded (columns r) base) (cache : cachedMultiples r rFive)
    (high : bit = 0#u64 ∨ bit = 16777216#u64) :
    absorb_encoded h r rFive word bit ⦃ out => live (columns out) ∧ value (columns out) % modulus =
      ((value (columns h) % modulus + word.val + base^4 * bit.val) * value (columns r)) % modulus ⦄ := by
  unfold absorb_encoded
  step with (source_limbs_columns word) as ⟨message, decoded⟩
  simp only [fixed_index4, lift, Aeneas.Std.bind_tc_ok]
  have bound : (4#usize).val < message.length := by simp [show (4#usize).val = 4 by decide]
  step with (Aeneas.Std.Array.update_spec message 4#usize _ bound) as ⟨tagged, taggedEq⟩
  have messageHigh : message.val[4]!.val = word.val / base^4 := by
    exact congrArg Columns.c4 decoded
  have exactTagged : columns tagged = { decodedColumns word.val with c4 := word.val / base^4 + bit.val } := by
    rw [taggedEq, fixed_set, decoded, encoded_high_limb _ _ (messageHigh ▸ top_lt _ (word_lt word)) high]
    rw [messageHigh]
  have bitBound : bit.val ≤ 2^24 := by rcases high with h | h <;> rw [h] <;> decide
  have taggedBound : bounded (columns tagged) base :=
    exactTagged ▸ decoded_bounded word.val bit.val (word_lt word) bitBound
  step with (source_absorb_polynomial_step h r rFive tagged state key taggedBound cache)
    as ⟨out, invariant, polynomial⟩
  refine ⟨invariant, ?_⟩
  rw [polynomial, polynomialStep, exactTagged, decoded_value, Nat.add_assoc]

/-- The exact Rust input path agrees with the RFC recurrence for every full
16-byte block, including the bit to the left of its 128 data bits. -/
theorem source_absorb_full_block_refines (h r : Words) (rFive : Multiples) (block : Bytes16)
    (state : live (columns h)) (key : bounded (columns r) base) (cache : cachedMultiples r rFive) :
    absorb_bytes h r rFive block 16777216#u64 ⦃ out => live (columns out) ∧ value (columns out) % modulus =
      ((value (columns h) % modulus + blockValue block + 2^128) * value (columns r)) % modulus ⦄ := by
  unfold absorb_bytes
  step with (source_load_block_refines block) as ⟨word, loaded⟩
  step with (source_absorb_encoded_refines h r rFive word 16777216#u64 state key cache (Or.inr rfl))
    as ⟨out, invariant, recurrence⟩
  exact ⟨invariant, by simpa only [loaded, blockValue, show base^4 * 16777216 = 2^128 by decide] using recurrence⟩

/-- The exact path for a final partial block consumes the marker supplied in
its padded input bytes and adds no extra bit at position 128. -/
theorem source_absorb_padded_final_block_refines (h r : Words) (rFive : Multiples) (block : Bytes16)
    (state : live (columns h)) (key : bounded (columns r) base) (cache : cachedMultiples r rFive) :
    absorb_bytes h r rFive block 0#u64 ⦃ out => live (columns out) ∧ value (columns out) % modulus =
      ((value (columns h) % modulus + blockValue block) * value (columns r)) % modulus ⦄ := by
  unfold absorb_bytes
  step with (source_load_block_refines block) as ⟨word, loaded⟩
  step with (source_absorb_encoded_refines h r rFive word 0#u64 state key cache (Or.inl rfl))
    as ⟨out, invariant, recurrence⟩
  exact ⟨invariant, by simpa only [loaded, blockValue, show (0#u64).val = 0 by decide, Nat.mul_zero, Nat.add_zero] using recurrence⟩

#print axioms source_limbs_columns
#print axioms source_load_block_refines
#print axioms source_clamped_key_refines
#print axioms source_absorb_encoded_refines
#print axioms source_absorb_full_block_refines
#print axioms source_absorb_padded_final_block_refines

end Abc.Refine.Poly1305.Bytes
