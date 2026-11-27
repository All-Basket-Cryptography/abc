import Abc.Sha256.Extracted.Funs
import ModelView

open Aeneas Aeneas.Std
open Aeneas.Std.Result Aeneas.Std.ControlFlow

namespace Abc.Refine.Sha256.Implementation

open Abc.Sha256.Extracted

private theorem endianBytes (width : Nat) (bits : BitVec (8 * width)) :
    bits.toBEBytes = Abc.Foundation.bytesBigEndian width bits.toNat := by
  have count : bits.toLEBytes.length = width := by
    rw [BitVec.toLEBytes_length]
    omega
  unfold BitVec.toBEBytes Abc.Foundation.bytesBigEndian
  apply List.ext_getElem
  · simp [count]
  · intro i left right
    rw [List.getElem_reverse, List.getElem_map, List.getElem_range]
    have index : bits.toLEBytes.length - 1 - i < bits.toLEBytes.length := by
      simpa using (show bits.toLEBytes.length - 1 - i < bits.toLEBytes.length by
        simp only [List.length_reverse] at left
        omega)
    apply (Byte.eq_iff _ _).mpr
    intro j hj
    rw [List.Inhabited_getElem_eq_getElem! _ _ index, BitVec.toLEBytes_getElem!_testBit _ _ _ hj]
    simp only [BitVec.getElem!_eq_testBit_toNat, count, Byte.testBit, BitVec.toNat_ofNat]
    rw [Nat.testBit_mod_two_pow]
    simp only [hj, decide_true, Bool.true_and]
    change bits.toNat.testBit (8 * (width - 1 - i) + j) =
      (bits.toNat / (2 ^ 8) ^ (width - 1 - i)).testBit j
    rw [← Nat.pow_mul, Nat.testBit_div_two_pow, Nat.add_comm]

private theorem updatedByte {n : Usize} (block : Aeneas.Std.Array U8 n) (i : Usize)
    (byte : U8) (j : Nat) (bound : i.val < n.val) :
    (block.set i byte).val[j]? = if i.val = j then some byte else block.val[j]? := by
  rw [Aeneas.Std.Array.set_val_eq]
  split
  next same =>
    subst j
    exact List.getElem?_set_self (by simpa)
  next different => exact List.getElem?_set_ne different

/-- The extracted zero-fill loop preserves bytes below its starting index. -/
theorem finalize_zero_fill (block : Aeneas.Std.Array U8 64#usize) (start : Usize)
    (bound : start.val ≤ 64) :
    Sha256.finalize_loop0 block start ⦃ out =>
      ∀ j < 64, out.val[j]? = if j < start.val then block.val[j]? else some 0#u8 ⦄ := by
  unfold Sha256.finalize_loop0
  apply loop.spec_decr_nat (fun (_, i) => 64 - i.val)
    (fun (current, i) => start.val ≤ i.val ∧ i.val ≤ 64 ∧
      ∀ j < 64, current.val[j]? =
        if start.val ≤ j ∧ j < i.val then some 0#u8 else block.val[j]?)
  · rintro ⟨current, i⟩ ⟨startBound, limit, content⟩
    dsimp only at startBound limit content ⊢
    unfold Sha256.finalize_loop0.body
    split
    next more =>
      have hMore : i.val < 64 := by simpa [BLOCK_BYTES] using more
      step as ⟨nextBlock, nextBlockEq⟩
      step as ⟨nextIndex, nextIndexEq⟩
      have hIndex : nextIndex.val = i.val + 1 := by scalar_tac
      refine ⟨by omega, by omega, ?_, by omega⟩
      intro j jBound
      rw [nextBlockEq, updatedByte current i 0#u8 j (by simpa using hMore), hIndex]
      by_cases atIndex : i.val = j
      · subst j
        simp [startBound]
      · rw [if_neg atIndex, content j jBound]
        have unchanged : (start.val ≤ j ∧ j < i.val) ↔
            (start.val ≤ j ∧ j < i.val + 1) := by omega
        simp [unchanged]
    next finished =>
      have hFinished : ¬ i.val < 64 := by simpa [BLOCK_BYTES] using finished
      simp only [WP.spec_ok]
      intro j jBound
      rw [content j jBound]
      by_cases h : j < start.val
      · simp [h, show ¬ start.val ≤ j by omega]
      · simp [h, show start.val ≤ j by omega, show j < i.val by omega]
  · refine ⟨Nat.le_refl _, bound, ?_⟩
    intro j _
    simp [show ¬ (start.val ≤ j ∧ j < start.val) by omega]

/-- The extracted length writer replaces the final eight bytes of the block. -/
theorem finalize_write_length (block : Aeneas.Std.Array U8 64#usize)
    (suffix : Aeneas.Std.Array U8 8#usize) :
    Sha256.finalize_loop1 block suffix 0#usize ⦃ out =>
      ∀ j < 64, out.val[j]? = if j < 56 then block.val[j]? else suffix.val[j - 56]? ⦄ := by
  unfold Sha256.finalize_loop1
  apply loop.spec_decr_nat (fun (_, i) => 8 - i.val)
    (fun (current, i) => i.val ≤ 8 ∧
      ∀ j < 64, current.val[j]? =
        if 56 ≤ j ∧ j < 56 + i.val then suffix.val[j - 56]? else block.val[j]?)
  · rintro ⟨current, i⟩ ⟨limit, content⟩
    dsimp only at limit content ⊢
    unfold Sha256.finalize_loop1.body
    split
    next more =>
      have hMore : i.val < 8 := by simpa using more
      step as ⟨byte, byteEq⟩
      step as ⟨atByte, atByteEq⟩
      step as ⟨nextBlock, nextBlockEq⟩
      step as ⟨nextIndex, nextIndexEq⟩
      have hAtByte : atByte.val = 56 + i.val := by scalar_tac
      have hIndex : nextIndex.val = i.val + 1 := by scalar_tac
      refine ⟨by omega, ?_, by omega⟩
      intro j jBound
      rw [nextBlockEq, updatedByte current atByte byte j (by simp; omega), hAtByte, hIndex]
      by_cases atIndex : 56 + i.val = j
      · subst j
        have inRange : 56 ≤ 56 + i.val ∧ 56 + i.val < 56 + (i.val + 1) := by omega
        have lengthBound : i.val < suffix.val.length := by simpa
        rw [if_pos inRange]
        simp only [if_true, Nat.add_sub_cancel_left,
          getElem?_pos suffix.val i.val lengthBound, byteEq]
      · rw [if_neg atIndex, content j jBound]
        have unchanged : (56 ≤ j ∧ j < 56 + i.val) ↔
            (56 ≤ j ∧ j < 56 + (i.val + 1)) := by omega
        simp [unchanged]
    next finished =>
      have hFinished : ¬ i.val < 8 := by simpa using finished
      simp only [WP.spec_ok]
      intro j jBound
      rw [content j jBound]
      by_cases h : j < 56
      · simp [h, show ¬ 56 ≤ j by omega]
      · simp [h, show 56 ≤ j by omega, show j < 56 + i.val by omega]
  · refine ⟨by simp, ?_⟩
    intro j _
    simp [show ¬ (56 ≤ j ∧ j < 56) by omega]

private def encodedByte (state : Aeneas.Std.Array U32 8#usize) (j : Nat) : Option U8 :=
  (core.num.U32.to_be_bytes (state.val[j / 4]?.getD 0#u32)).val[j % 4]?

/-- Each output byte of the extracted encoder is in its big-endian register position. -/
theorem finalize_encode (state : Aeneas.Std.Array U32 8#usize)
    (buffer : Aeneas.Std.Array U8 32#usize) :
    Sha256.finalize_loop2 state buffer 0#usize ⦃ out =>
      ∀ j < 32, out.val[j]? = encodedByte state j ⦄ := by
  unfold Sha256.finalize_loop2
  apply loop.spec_decr_nat (fun (_, i) => 8 - i.val)
    (fun (current, i) => i.val ≤ 8 ∧ ∀ j < 4 * i.val, current.val[j]? = encodedByte state j)
  · rintro ⟨current, i⟩ ⟨limit, content⟩
    dsimp only at limit content ⊢
    unfold Sha256.finalize_loop2.body
    simp only [lift, bind_tc_ok]
    split
    next more =>
      have hMore : i.val < 8 := by
        simpa [Slice.len_val, Aeneas.Std.Array.length_to_slice] using more
      step as ⟨word, wordEq⟩
      step as ⟨b0, b0Eq⟩
      step as ⟨b1, b1Eq⟩
      step as ⟨b2, b2Eq⟩
      step as ⟨b3, b3Eq⟩
      step as ⟨offset, offsetEq⟩
      step as ⟨buffer1, buffer1Eq⟩
      step as ⟨p1, p1Eq⟩
      step as ⟨buffer2, buffer2Eq⟩
      step as ⟨p2, p2Eq⟩
      step as ⟨buffer3, buffer3Eq⟩
      step as ⟨p3, p3Eq⟩
      step as ⟨buffer4, buffer4Eq⟩
      step as ⟨nextIndex, nextIndexEq⟩
      have hOffset : offset.val = 4 * i.val := by scalar_tac
      have hP1 : p1.val = 4 * i.val + 1 := by scalar_tac
      have hP2 : p2.val = 4 * i.val + 2 := by scalar_tac
      have hP3 : p3.val = 4 * i.val + 3 := by scalar_tac
      have hIndex : nextIndex.val = i.val + 1 := by scalar_tac
      refine ⟨by omega, ?_, by omega⟩
      intro j jBound
      rw [buffer4Eq, updatedByte buffer3 p3 b3 j (by simp; omega), hP3,
        buffer3Eq, updatedByte buffer2 p2 b2 j (by simp; omega), hP2,
        buffer2Eq, updatedByte buffer1 p1 b1 j (by simp; omega), hP1,
        buffer1Eq, updatedByte current offset b0 j (by simp; omega), hOffset]
      by_cases earlier : j < 4 * i.val
      · have old := content j earlier
        simpa [show 4 * i.val ≠ j by omega, show 4 * i.val + 1 ≠ j by omega,
          show 4 * i.val + 2 ≠ j by omega, show 4 * i.val + 3 ≠ j by omega] using old
      · have offsets : j = 4 * i.val ∨ j = 4 * i.val + 1 ∨
          j = 4 * i.val + 2 ∨ j = 4 * i.val + 3 := by omega
        have wordBound : i.val < state.val.length := by simpa
        have wordLookup : state.val[i.val]?.getD 0#u32 = word := by
          rw [getElem?_pos state.val i.val wordBound, wordEq]
          rfl
        rcases offsets with rfl | rfl | rfl | rfl
        all_goals
          simp [encodedByte, wordLookup, b0Eq, b1Eq, b2Eq, b3Eq,
            show (4 * i.val + 1) / 4 = i.val by omega,
            show (4 * i.val + 2) / 4 = i.val by omega,
            show (4 * i.val + 3) / 4 = i.val by omega,
            show (4 * i.val + 1) % 4 = 1 by omega,
            show (4 * i.val + 2) % 4 = 2 by omega,
            show (4 * i.val + 3) % 4 = 3 by omega]
    next finished =>
      have hFinished : ¬ i.val < 8 := by
        simpa [Slice.len_val, Aeneas.Std.Array.length_to_slice] using finished
      simp only [WP.spec_ok]
      intro j jBound
      exact content j (by omega)
  · refine ⟨by simp, ?_⟩
    intro j h
    simp at h

private theorem zeroPadding_view (block : Aeneas.Std.Array U8 64#usize)
    (buffered : Usize) (bound : buffered.val < 64) (out : Aeneas.Std.Array U8 64#usize)
    (zeroed : ∀ j < 64, out.val[j]? =
      if j < buffered.val + 1 then (block.set buffered 128#u8).val[j]? else some 0#u8) :
    bytesView out.val = bytesView (block.val.take buffered.val) ++ [0x80] ++
      List.replicate (63 - buffered.val) 0 := by
  have prefixLength : (block.val.take buffered.val).length = buffered.val := by simp; omega
  have raw : out.val = block.val.take buffered.val ++ [128#u8] ++
      List.replicate (63 - buffered.val) 0#u8 := by
    apply List.ext_getElem?
    intro j
    by_cases jBound : j < 64
    · rw [zeroed j jBound, List.getElem?_append, List.length_append, prefixLength]
      rw [updatedByte block buffered 128#u8 j (by simpa using bound)]
      by_cases earlier : j < buffered.val
      · have different : buffered.val ≠ j := by omega
        rw [List.getElem?_append, prefixLength]
        simp [earlier, show j < buffered.val + 1 by omega, different]
      · by_cases atMarker : j = buffered.val
        · subst j
          simp [prefixLength]
        · have after : ¬ j < buffered.val + 1 := by omega
          have inZeros : j - (buffered.val + 1) < 63 - buffered.val := by omega
          simp [after, inZeros]
    · have beyond : buffered.val + (63 - buffered.val + 1) ≤ j := by omega
      simp [jBound, prefixLength, beyond]
  simp [raw, bytesView]

private theorem lengthSuffix_view (block : Aeneas.Std.Array U8 64#usize)
    (suffix : Aeneas.Std.Array U8 8#usize) (out : Aeneas.Std.Array U8 64#usize)
    (written : ∀ j < 64, out.val[j]? = if j < 56 then block.val[j]? else suffix.val[j - 56]?) :
    bytesView out.val = (bytesView block.val).take 56 ++ bytesView suffix.val := by
  have raw : out.val = block.val.take 56 ++ suffix.val := by
    apply List.ext_getElem?
    intro j
    by_cases jBound : j < 64
    · rw [written j jBound, List.getElem?_append]
      have taken : (block.val.take 56).length = 56 := by simp
      rw [taken]
      by_cases early : j < 56
      · simp only [if_pos early, List.getElem?_take_of_lt early]
      · simp only [if_neg early]
    · simp [jBound]
  simp [raw, bytesView_take]

private theorem wordBytes_view (word : U32) :
    bytesView (core.num.U32.to_be_bytes word).val =
      Abc.Foundation.bytesBigEndian 4 word.val := by
  simpa [bytesView, core.num.U32.to_be_bytes, Function.comp_def] using endianBytes 4 word.bv

private theorem counterBytes_view (word : U64) :
    bytesView (core.num.U64.to_be_bytes word).val =
      Abc.Foundation.bytesBigEndian 8 word.val := by
  simpa [bytesView, core.num.U64.to_be_bytes, Function.comp_def] using endianBytes 8 word.bv

private def wordBytes (word : U32) : List (BitVec 8) :=
  bytesView (core.num.U32.to_be_bytes word).val

private theorem wordBytes_length (word : U32) : (wordBytes word).length = 4 := by
  simp [wordBytes]

private theorem registersByte (words : List U32) (j : Nat) :
    (words.flatMap wordBytes)[j]? = (words[j / 4]?).bind (fun word => (wordBytes word)[j % 4]?) := by
  induction words generalizing j with
  | nil => simp
  | cons word rest ih =>
    rw [List.flatMap_cons, List.getElem?_append, wordBytes_length]
    by_cases early : j < 4
    · simp [early, Nat.div_eq_of_lt early, Nat.mod_eq_of_lt early]
    · simp only [if_neg early, ih]
      have quotient : j / 4 = (j - 4) / 4 + 1 := by omega
      have offset : (j - 4) % 4 = j % 4 := by omega
      simp [quotient, offset]

private theorem encodedState_view (state : Aeneas.Std.Array U32 8#usize)
    (out : Aeneas.Std.Array U8 32#usize)
    (written : ∀ j < 32, out.val[j]? = encodedByte state j) :
    bytesView out.val = Abc.Spec.Sha256.encode (stateView state) := by
  have encoding : state.val.flatMap wordBytes = Abc.Spec.Sha256.encode (stateView state) := by
    have registers : state.val = (List.range 8).map (fun i => state.val[i]?.getD 0#u32) := by
      apply List.ext_getElem?
      intro j
      by_cases h : j < 8
      · simp [h]
      · simp [h]
    nth_rw 1 [registers]
    simp only [List.flatMap_map, wordBytes, wordBytes_view]
    rfl
  rw [← encoding]
  apply List.ext_getElem?
  intro j
  simp only [bytesView, List.getElem?_map, registersByte]
  by_cases h : j < 32
  · have inState : j / 4 < state.val.length := by simp; omega
    rw [written j h, encodedByte, getElem?_pos state.val (j / 4) inState]
    simp [wordBytes, bytesView, List.getElem?_map]
  · have afterState : state.val.length ≤ j / 4 := by simp; omega
    rw [List.getElem?_eq_none (show out.val.length ≤ j by simp; omega),
      List.getElem?_eq_none afterState]
    rfl

private theorem paddingPrefix (pending : Abc.Spec.Sha256.Message) (short : pending.length < 56) :
    (pending ++ [0x80] ++ List.replicate (63 - pending.length) 0).take 56 =
      pending ++ [0x80] ++ List.replicate (55 - pending.length) 0 := by
  have prefixLength : (pending ++ [0x80]).length = pending.length + 1 := by simp
  rw [List.take_append, List.take_of_length_le (by omega), List.take_replicate, prefixLength]
  congr 2
  omega

private theorem finalize_finish
    (compressSpec : ∀ (state : Aeneas.Std.Array U32 8#usize) (input : Slice U8),
      input.val.length = 64 →
      compress state input ⦃ out =>
        stateView out = Abc.Spec.Sha256.compress (stateView state) (bytesView input.val) ⦄)
    (state : Aeneas.Std.Array U32 8#usize) (block : Aeneas.Std.Array U8 64#usize)
    (length : U64) (valid : Abc.Spec.Sha256.byteLengthAllowed length.val) :
    (do
      let i ← length * 8#u64
      let suffix ← lift (core.num.U64.to_be_bytes i)
      let ready ← Sha256.finalize_loop1 block suffix 0#usize
      let input ← lift (Aeneas.Std.Array.to_slice ready)
      let state' ← compress state input
      Sha256.finalize_loop2 state' (Aeneas.Std.Array.repeat 32#usize 0#u8) 0#usize)
    ⦃ out => bytesView out.val = Abc.Spec.Sha256.encode
      (Abc.Spec.Sha256.compress (stateView state) ((bytesView block.val).take 56 ++
        Abc.Foundation.bytesBigEndian 8 (length.val * 8))) ⦄ := by
  have fits := Streaming.bitLength_fits length.val valid
  have fitsMax : length.val * 8 ≤ U64.max := by
    change length.val * 8 < 18446744073709551616 at fits
    rw [U64.max_eq]
    omega
  step as ⟨bitLength, bitLengthEq⟩
  have bitLengthVal : bitLength.val = length.val * 8 := by scalar_tac
  simp only [lift, bind_tc_ok]
  step with finalize_write_length as ⟨ready, readyEq⟩
  have blockBytes := lengthSuffix_view block (core.num.U64.to_be_bytes bitLength) ready readyEq
  rw [counterBytes_view, bitLengthVal] at blockBytes
  step with compressSpec as ⟨state', stateEq⟩
  step with finalize_encode as ⟨out, outEq⟩
  rw [encodedState_view state' out outEq, stateEq, Aeneas.Std.Array.val_to_slice, blockBytes]

/-- Byte-level refinement of the extracted Rust finalizer given compression refinement. -/
theorem finalize_refines_of_compress
    (compressSpec : ∀ (state : Aeneas.Std.Array U32 8#usize) (input : Slice U8),
      input.val.length = 64 →
      compress state input ⦃ out =>
        stateView out = Abc.Spec.Sha256.compress (stateView state) (bytesView input.val) ⦄)
    (self : Sha256) (message : Abc.Spec.Sha256.Message)
    (represents : Streaming.Represents Abc.Spec.Sha256.initial Abc.Spec.Sha256.compress
      (streamView self) message) :
    Sha256.finalize self ⦃ out => some (bytesView out.val) = Abc.Spec.Sha256.digest message ⦄ := by
  let pending := (streamView self).pending
  have pendingEq : pending = bytesView (self.block.val.take self.buffered.val) := rfl
  have buffered : self.buffered.val < 64 := by
    obtain ⟨_, partition, _, _, _⟩ := represents
    have short : pending.length < 64 := partition.short
    rw [pendingEq, bytesView_length, List.length_take, Aeneas.Std.Array.property] at short
    simp at short
    omega
  have pendingLength : pending.length = self.buffered.val := by
    rw [pendingEq, bytesView_length, List.length_take, Aeneas.Std.Array.property]
    simp; omega
  have valid : Abc.Spec.Sha256.byteLengthAllowed self.length.val := by
    obtain ⟨_, _, lengthEq, allowed, _⟩ := represents
    change self.length.val = message.length at lengthEq
    simpa [lengthEq] using allowed
  rw [← Streaming.finalize_refines_digest represents]
  unfold Sha256.finalize
  step as ⟨marked, markedEq⟩
  step as ⟨start, startEq⟩
  have startVal : start.val = self.buffered.val + 1 := by scalar_tac
  step with finalize_zero_fill as ⟨padded, paddedEq⟩
  rw [markedEq, startVal] at paddedEq
  have paddedBytes := zeroPadding_view self.block self.buffered buffered padded paddedEq
  rw [← pendingEq, ← pendingLength] at paddedBytes
  by_cases short : self.buffered.val < 56
  · have branch : ¬ self.buffered ≥ 56#usize := by simpa using short
    simp only [if_neg branch, lift, bind_tc_ok]
    have post := finalize_finish compressSpec self.state padded self.length valid
    obtain ⟨out, ran, value⟩ := WP.spec_imp_exists post
    refine (WP.spec_equiv_exists _ _).mpr ⟨out, ?_, ?_⟩
    · change (do
        let bits ← self.length * 8#u64
        let ready ← Sha256.finalize_loop1 padded (core.num.U64.to_be_bytes bits) 0#usize
        let state ← compress self.state ready.to_slice
        Sha256.finalize_loop2 state (Aeneas.Std.Array.repeat 32#usize 0#u8) 0#usize) = ok out
      simpa only [lift, bind_tc_ok] using ran
    · rw [value, paddedBytes, paddingPrefix _ (by omega)]
      simp [Streaming.finalizeView, Streaming.finalBlocks, pending, short, streamView]
  · have branch : self.buffered ≥ 56#usize := by simpa using short
    simp only [if_pos branch, lift, bind_tc_ok]
    step with compressSpec as ⟨nextState, nextStateEq⟩
    rw [Aeneas.Std.Array.val_to_slice, paddedBytes] at nextStateEq
    have post := finalize_finish compressSpec nextState
      (Aeneas.Std.Array.repeat 64#usize 0#u8) self.length valid
    obtain ⟨out, ran, value⟩ := WP.spec_imp_exists post
    simp only [lift, bind_tc_ok] at ran
    rw [ran, WP.spec_ok, value, nextStateEq]
    simp [Streaming.finalizeView, Streaming.finalBlocks, pending, short, streamView, bytesView]

end Abc.Refine.Sha256.Implementation
