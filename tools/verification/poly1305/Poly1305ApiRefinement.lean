import Poly1305FinalRefinement
import Poly1305ByteRefinement
import Poly1305SourceRefinement

namespace Abc.Refine.Poly1305.Api

open Aeneas Aeneas.Std Result
open Abc.Poly1305.Extracted
open Abc.Refine.Poly1305 (columns cachedMultiples source_key_multiples_refines)
open Abc.Refine.Poly1305.Bytes (blockValue fromLEBytes_toNat source_load_block_refines
  source_clamped_key_refines source_absorb_encoded_refines)
open Abc.Refine.Poly1305.Final (source_finish_tag_value)
open Abc.Spec.Poly1305.Go (bounded base live value modulus)
open Abc.Foundation (decodeLittleEndian)

set_option maxHeartbeats 4500000
set_option maxRecDepth 4096

private abbrev Key := Aeneas.Std.Array U8 32#usize
private abbrev Block := Aeneas.Std.Array U8 16#usize

private theorem byte_index {n : Usize} (a : Aeneas.Std.Array U8 n) (i : Usize)
    (bound : i.val < n.val) : a.index_usize i = .ok a.val[i.val]! := by
  have inside : i.val < a.val.length := by simpa using bound
  simp [Aeneas.Std.Array.index_usize, Aeneas.Std.Array.getElem?_Usize_eq,
    getElem?_pos a.val i.val inside]

private theorem key_length (key : Key) : key.val.length = 32 := by
  have h := key.property
  simpa only [show (32#usize).val = 32 by decide] using h

private theorem slice_key (key : Key) (start : Nat) (inside : start + 16 ≤ 32) :
    (List.range' start 16).map (fun i => key.val[i]!) = (key.val.drop start).take 16 := by
  apply List.ext_getElem (by simp; omega)
  intro i left right
  have iBound : i < 16 := by simpa using left
  have bound : start + i < key.val.length := by rw [key_length]; omega
  rw [List.getElem_map, List.getElem_range', Nat.one_mul, List.getElem_take, List.getElem_drop,
    getElem!_pos key.val (start + i) bound]

/-- The extracted split preserves all bytes and their order in each key half. -/
theorem source_split_key_refines (key : Key) :
    split_key key ⦃ lo hi => lo.val = key.val.take 16 ∧ hi.val = key.val.drop 16 ⦄ := by
  simp (disch := decide) only [split_key, byte_index, Aeneas.Std.bind_tc_ok, WP.spec_ok]
  constructor
  · simp only [Aeneas.Std.Array.make_val]
    let indices := [0#usize, 1#usize, 2#usize, 3#usize, 4#usize, 5#usize, 6#usize, 7#usize,
      8#usize, 9#usize, 10#usize, 11#usize, 12#usize, 13#usize, 14#usize, 15#usize]
    change indices.map ((fun i : Nat => key.val[i]!) ∘ fun i : Usize => i.val) = key.val.take 16
    rw [← List.map_map, show indices.map (fun i => i.val) = List.range' 0 16 by decide]
    simpa only [List.drop_zero] using slice_key key 0 (by decide)
  · simp only [Aeneas.Std.Array.make_val]
    let indices := [16#usize, 17#usize, 18#usize, 19#usize, 20#usize, 21#usize, 22#usize, 23#usize,
      24#usize, 25#usize, 26#usize, 27#usize, 28#usize, 29#usize, 30#usize, 31#usize]
    change indices.map ((fun i : Nat => key.val[i]!) ∘ fun i : Usize => i.val) = key.val.drop 16
    rw [← List.map_map, show indices.map (fun i => i.val) = List.range' 16 16 by decide]
    have tail : (key.val.drop 16).take 16 = key.val.drop 16 := by
      apply List.take_of_length_le
      simp
    exact (slice_key key 16 (by decide)).trans tail

structure Ready (state : Poly1305) : Prop where
  keyFits : bounded (columns state.r) base
  keyCache : cachedMultiples state.r state.r_times_five
  accumulatorFits : live (columns state.h)
  pendingFits : state.buffered.val < 16

private def clamp (bytes : List (BitVec 8)) : Nat :=
  decodeLittleEndian bytes &&& 0x0ffffffc0ffffffc0ffffffc0fffffff

/-- The actual public constructor binds the two key halves to the RFC
multiplier and pad and initializes an empty, ready streaming state. -/
theorem source_new_refines (key : Key) :
    Poly1305.new key ⦃ state => Ready state ∧
      value (columns state.r) = clamp ((key.val.take 16).map U8.bv) ∧
      state.pad.val = decodeLittleEndian ((key.val.drop 16).map U8.bv) ∧
      value (columns state.h) = 0 ∧ state.buffered.val = 0 ∧
      state.pending.val = List.replicate 16 0#u8 ⦄ := by
  unfold Poly1305.new
  step with (source_split_key_refines key) as ⟨lo, hi, loEq, hiEq⟩
  step with (source_clamped_key_refines lo) as ⟨r, keyBound, keyVal⟩
  step with (source_key_multiples_refines r keyBound) as ⟨cache, cached⟩
  step with (source_load_block_refines hi) as ⟨pad, padVal⟩
  have hEmpty : columns (Aeneas.Std.Array.repeat 5#usize 0#u64) = ⟨0, 0, 0, 0, 0⟩ := by rfl
  have zeroBound : (0#usize).val < 16 := by decide
  refine ⟨⟨keyBound, cached, ?_, zeroBound⟩, ?_, ?_, ?_, rfl, rfl⟩
  · rw [hEmpty]
    simp [live, base]
  · simpa only [blockValue, loEq, clamp] using keyVal
  · simpa only [hiEq] using padVal
  · rw [hEmpty]
    decide

private theorem decode_cons (byte : BitVec 8) (bytes : List (BitVec 8)) :
    decodeLittleEndian (byte :: bytes) = byte.toNat + 256 * decodeLittleEndian bytes := by
  simp only [decodeLittleEndian, Abc.Foundation.decodeBigEndian, List.reverse_cons,
    List.foldl_append, List.foldl_cons, List.foldl_nil, Nat.add_comm]

private theorem decode_append (front rest : List (BitVec 8)) :
    decodeLittleEndian (front ++ rest) = decodeLittleEndian front + 256^front.length * decodeLittleEndian rest := by
  induction front with
  | nil => simp [decodeLittleEndian, Abc.Foundation.decodeBigEndian]
  | cons byte tail ih =>
    simp only [List.cons_append, decode_cons, ih, List.length_cons, Nat.pow_succ', Nat.mul_add,
      Nat.mul_assoc, Nat.add_assoc]

private theorem decode_bound (bytes : List (BitVec 8)) : decodeLittleEndian bytes < 256^bytes.length := by
  have within := (BitVec.fromLEBytes bytes).isLt
  rw [fromLEBytes_toNat, Nat.pow_mul] at within
  exact within

private theorem decode_prefix (bytes : List (BitVec 8)) (length : Nat) (fits : length ≤ bytes.length) :
    decodeLittleEndian bytes % 256^length = decodeLittleEndian (bytes.take length) := by
  have split := decode_append (bytes.take length) (bytes.drop length)
  rw [List.take_append_drop, List.length_take, Nat.min_eq_left fits] at split
  have prefixFits := decode_bound (bytes.take length)
  rw [List.length_take, Nat.min_eq_left fits] at prefixFits
  rw [split, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt prefixFits]

private theorem marker_shift (count : Usize) (fits : count.val < 128) :
    (1#u128 <<< count) = .ok (⟨(1#128) <<< count.val⟩ : U128) := by
  change (if count.val < 128 then Result.ok (⟨(1#128) <<< count.val⟩ : U128)
    else Result.fail .integerOverflow) = _
  rw [if_pos fits]

/-- The actual tail encoder ignores stale bytes above the logical end and
adds exactly `256^length` to the little-endian integer of the live prefix. -/
theorem source_encode_partial_refines (block : Block) (length : Usize) (fits : length.val < 16) :
    encode_partial block length ⦃ out =>
      out.val = decodeLittleEndian ((block.val.map U8.bv).take length.val) + 256^length.val ⦄ := by
  unfold encode_partial
  have fitsProduct : (8#usize).val * length.val ≤ UScalar.max .Usize := by scalar_tac
  step with (UScalar.mul_spec fitsProduct) as ⟨count, countEq⟩
  have countValue : count.val = 8 * length.val := countEq
  have countFits : count.val < 128 := by omega
  rw [marker_shift count countFits, Aeneas.Std.bind_tc_ok]
  let marker : U128 := ⟨(1#128) <<< count.val⟩
  have markerVal : marker.val = 2^count.val := by
    change ((1#128) <<< count.val).toNat = _
    rw [BitVec.toNat_shiftLeft, Nat.shiftLeft_eq]
    change (1 * 2^count.val) % 2^128 = _
    rw [Nat.one_mul, Nat.mod_eq_of_lt (Nat.pow_lt_pow_right (a := 2) (by decide) countFits)]
  step with (source_load_block_refines block) as ⟨word, loaded⟩
  have maskBound : (1#u128).val ≤ marker.val := by rw [markerVal]; exact Nat.one_le_pow _ _ (by decide)
  step with (UScalar.sub_spec maskBound) as ⟨mask, maskValue⟩
  simp only [lift, Aeneas.Std.bind_tc_ok, WP.spec_ok]
  change ((word.bv &&& mask.bv) ||| marker.bv).toNat = _
  rw [BitVec.toNat_or, BitVec.toNat_and]
  change word.val &&& mask.val ||| marker.val = _
  rw [maskValue, markerVal, Nat.and_two_pow_sub_one_eq_mod]
  have lo : word.val % 2^count.val < 2^count.val := Nat.mod_lt _ (by positivity)
  rw [Nat.or_comm, ← show 2^count.val + word.val % 2^count.val =
      2^count.val ||| word.val % 2^count.val from by
        simpa only [Nat.mul_one] using Nat.two_pow_add_eq_or_of_lt lo 1]
  rw [countValue, Nat.pow_mul, loaded, decode_prefix _ _ (by simp; omega), Nat.add_comm]

private def finalResidue (state : Poly1305) : Nat :=
  let h := value (columns state.h) % modulus
  let tail := (state.pending.val.map U8.bv).take state.buffered.val
  if state.buffered.val = 0 then h
  else ((h + decodeLittleEndian tail + 256^state.buffered.val) * value (columns state.r)) % modulus

/-- The actual public finalizer consumes a final tail exactly when one is
present, ignores stale bytes past it, and emits the RFC integer tag. -/
theorem source_finalize_refines (state : Poly1305) (ready : Ready state) :
    Poly1305.finalize state ⦃ out => blockValue out = (finalResidue state + state.pad.val) % 2^128 ⦄ := by
  unfold Poly1305.finalize
  by_cases empty : state.buffered = 0#usize
  · simp only [empty, if_true, Aeneas.Std.bind_tc_ok]
    refine WP.spec_mono (source_finish_tag_value state.h state.pad ready.accumulatorFits) ?_
    intro out finished
    simpa only [finalResidue, empty, show (0#usize).val = 0 by decide, if_true] using finished
  · simp only [if_neg empty]
    have pending : state.buffered.val ≠ 0 := by
      intro same
      exact empty (UScalar.eq_of_val_eq same)
    step with (source_encode_partial_refines state.pending state.buffered ready.pendingFits)
      as ⟨word, encoded⟩
    step with (source_absorb_encoded_refines state.h state.r state.r_times_five word 0#u64
      ready.accumulatorFits ready.keyFits ready.keyCache (Or.inl rfl)) as ⟨h, hLive, absorbed⟩
    step with (source_finish_tag_value h state.pad hLive) as ⟨out, finished⟩
    simpa only [absorbed, encoded, finalResidue, if_neg pending, show (0#u64).val = 0 by decide,
      Nat.mul_zero, Nat.add_zero, Nat.add_assoc] using finished

#print axioms source_split_key_refines
#print axioms source_new_refines
#print axioms source_encode_partial_refines
#print axioms source_finalize_refines

end Abc.Refine.Poly1305.Api
