import ChaCha20Stream
import ChaCha20QuarterRoundRefinement

namespace Abc.Refine.ChaCha20

open Aeneas Aeneas.Std
open Aeneas.Std.Result Aeneas.Std.ControlFlow
open Abc.ChaCha20.Extracted Abc.Spec.ChaCha20

set_option maxHeartbeats 1500000

private abbrev SliceBytes := Slice U8
private abbrev ByteArray := Aeneas.Std.Array U8 64#usize

private def byteAt (input : SliceBytes) (index : Nat) : BitVec 8 := input.val[index]!.bv

private theorem last_counter_test (length counter : Nat)
    (positive : 0 < length) (counterBound : counter < counterDomain) :
    (length - 1) / 64 > 4294967295 - counter ↔ ¬ admissible counter length := by
  unfold admissible blockCount counterDomain at *
  omega

private theorem usize_cast_u64 (value : Usize) :
    (UScalar.cast .U64 value).val = value.val := by
  have bound := value.hBounds
  rw [UScalar.cast_val_eq]
  apply Nat.mod_eq_of_lt
  change value.val < 18446744073709551616
  obtain bits | bits := System.Platform.numBits_eq <;> simp [UScalarTy.numBits, bits] at bound <;> omega

/-- The source preflight accepts exactly the RFC counter domain plus ABC's
empty-message case. All subtraction, division and casting operations succeed. -/
theorem source_counter_exhausted_refines (length : Usize) (counter : U32) :
    counter_exhausted length counter
      ⦃ exhausted => exhausted = decide (counterDomain - counter.val < blockCount length.val) ⦄ := by
  unfold counter_exhausted
  by_cases empty : length = 0#usize
  · rw [if_pos empty, empty]
    simp [WP.spec_ok, blockCount]
  · rw [if_neg empty]
    have positive : 0 < length.val := by
      apply Nat.pos_of_ne_zero
      intro zero
      exact empty (UScalar.eq_of_val_eq (by simpa using zero))
    have bounded : counter.val < counterDomain := by
      change counter.val < 4294967296
      scalar_tac
    simp only [lift, Aeneas.Std.bind_tc_ok, BLOCK_BYTES]
    step as ⟨last, lastEq⟩
    step as ⟨blockIndex, blockEq⟩
    step as ⟨remaining, remainingEq⟩
    have lastNat : last.val = length.val - 1 := by scalar_tac
    have blockNat : blockIndex.val = last.val / 64 := by scalar_tac
    have roomNat : remaining.val = 4294967295 - counter.val := by scalar_tac
    have shifted : remaining < UScalar.cast .U64 blockIndex ↔
        (length.val - 1) / 64 > 4294967295 - counter.val := by
      change remaining.val < (UScalar.cast .U64 blockIndex).val ↔ _
      rw [roomNat, usize_cast_u64, blockNat, lastNat]
    have comparison : (remaining < UScalar.cast .U64 blockIndex) ↔
        counterDomain - counter.val < blockCount length.val := by
      simpa [admissible] using shifted.trans (last_counter_test length.val counter.val positive bounded)
    simp [comparison]

/-- The extracted byte step returns a slice with only the designated XOR write. -/
theorem source_xor_byte_refines (input : SliceBytes) (index : Usize) (pad : U8)
    (within : index.val < input.val.length) :
    xor_byte input index pad
      ⦃ output => output = input.set index ⟨byteAt input index.val ^^^ pad.bv⟩ ⦄ := by
  unfold xor_byte
  simp only [lift, Aeneas.Std.bind_tc_ok]
  step as ⟨old, oldEq⟩
  step as ⟨output, outputEq⟩
  rw [outputEq, oldEq]
  simp [byteAt, within]
  rfl

private theorem byteAt_set (input : SliceBytes) (index : Usize) (value : U8)
    (within : index.val < input.val.length) (j : Nat) :
    byteAt (input.set index value) j =
      if j = index.val then value.bv else byteAt input j := by
  change (input.setAtNat index.val value).val[j]!.bv = _
  by_cases location : j = index.val
  · subst j
    rw [if_pos rfl, Slice.getElem!_Nat_setAtNat_eq]
    exact within
  · rw [if_neg location, Slice.getElem!_Nat_setAtNat_ne _ _ _ _ (Ne.symm location)]
    rfl

private def rangeEffect (before after : SliceBytes) (start upto : Nat) (pad : ByteArray) : Prop :=
  after.val.length = before.val.length ∧
    ∀ index, index < before.val.length →
      byteAt after index =
        if start ≤ index ∧ index < upto then
          byteAt before index ^^^ pad.val[index - start]!.bv
        else byteAt before index

private theorem rangeStep (before after : SliceBytes) (start amt : Nat) (pad : ByteArray)
    (address : Usize) (location : address.val = start + amt)
    (room : start + amt < before.val.length)
    (prior : rangeEffect before after start (start + amt) pad) :
    rangeEffect before (after.set address ⟨byteAt after address.val ^^^ pad.val[amt]!.bv⟩)
      start (start + (amt + 1)) pad := by
  obtain ⟨lenEq, readEq⟩ := prior
  refine ⟨by simpa using lenEq, ?_⟩
  intro index inside
  have writeInside : address.val < after.val.length := by omega
  rw [byteAt_set _ _ _ writeInside]
  by_cases indexAtWrite : index = address.val
  · rw [if_pos indexAtWrite, if_pos (by omega), indexAtWrite]
    rw [readEq address.val (by omega), if_neg (by omega)]
    have offset : address.val - start = amt := by omega
    rw [offset]
  · rw [if_neg indexAtWrite, readEq _ inside]
    have unchanged : (start ≤ index ∧ index < start + (amt + 1)) ↔ (start ≤ index ∧ index < start + amt) := by
      omega
    simp only [unchanged]

/-- The exact inner loop visits every byte of the supplied block prefix,
terminates, and preserves the bytes outside the write interval. -/
theorem source_xor_block_loop_refines (input : SliceBytes) (start : Usize) (pad : ByteArray)
    (count : Usize) (countBound : count.val ≤ 64) (inInput : start.val + count.val ≤ input.val.length) :
    xor_block_loop input start pad count 0#usize
      ⦃ output => rangeEffect input output start.val (start.val + count.val) pad ⦄ := by
  unfold xor_block_loop
  refine loop.spec_decr_nat
    (fun state : SliceBytes × Usize => count.val - state.2.val)
    (fun state => state.2.val ≤ count.val ∧
      rangeEffect input state.1 start.val (start.val + state.2.val) pad) _ _ _ ?_ ?_
  · rintro ⟨current, index⟩ ⟨indexBound, writes⟩
    dsimp only at indexBound writes
    unfold xor_block_loop.body
    dsimp only
    by_cases loopGuard : index < count
    · rw [if_pos loopGuard]
      have beforeEnd : index.val < count.val := by exact loopGuard
      have amountFits : start.val + index.val < input.val.length := by omega
      have sameLength := writes.1
      have padBound : index.val < pad.val.length := by scalar_tac
      step as ⟨address, addressEq⟩
      have addressVal : address.val = start.val + index.val := by scalar_tac
      have addressBound : address.val < current.val.length := by omega
      step as ⟨byte, byteEq⟩
      step with (source_xor_byte_refines current address byte addressBound) as ⟨updated, updateEq⟩
      step as ⟨next, nextEq⟩
      have nextVal : next.val = index.val + 1 := by scalar_tac
      refine ⟨by omega, ?_, by omega⟩
      rw [nextVal, updateEq, byteEq, ← getElem!_pos pad.val index.val padBound]
      exact rangeStep input current start.val index.val pad address addressVal amountFits writes
    · rw [if_neg loopGuard]
      simp only [WP.spec_ok]
      have finished : index.val = count.val := by
        have stopped : ¬ index.val < count.val := by exact loopGuard
        omega
      simpa only [← finished] using writes
  · refine ⟨by scalar_tac, rfl, ?_⟩
    intro index inside
    simp

/-- The source derives the exact final partial-block length and applies only
that many pad bytes. For a non-empty remaining message the offset advances. -/
theorem source_xor_block_refines (input : SliceBytes) (start : Usize) (pad : ByteArray)
    (startBound : start.val ≤ input.val.length) :
    xor_block input start pad
      ⦃ output =>
        output.1.val = start.val + min 64 (input.val.length - start.val) ∧
        rangeEffect input output.2 start.val output.1.val pad ⦄ := by
  unfold xor_block
  step as ⟨remaining, remainingEq⟩
  have remainingVal : remaining.val = input.val.length - start.val := by scalar_tac
  have chooseCount :
      (if remaining < BLOCK_BYTES then ok remaining else ok BLOCK_BYTES)
        ⦃ count => count.val = min 64 (input.val.length - start.val) ⦄ := by
    by_cases short : remaining < BLOCK_BYTES
    · have smaller : remaining.val < 64 := by simpa [BLOCK_BYTES] using short
      rw [if_pos short]
      simp [WP.spec_ok, ← remainingVal, Nat.min_eq_right (by omega : remaining.val ≤ 64)]
    · have large : 64 ≤ remaining.val := by simpa [BLOCK_BYTES] using short
      rw [if_neg short]
      simp [WP.spec_ok, BLOCK_BYTES, ← remainingVal, Nat.min_eq_left large]
  step with chooseCount as ⟨count, countEq⟩
  have countBound : count.val ≤ 64 := by rw [countEq]; exact Nat.min_le_left _ _
  have inInput : start.val + count.val ≤ input.val.length := by
    have room := Nat.min_le_right 64 (input.val.length - start.val)
    omega
  step with (source_xor_block_loop_refines input start pad count countBound inInput) as ⟨updated, writes⟩
  step as ⟨next, nextEq⟩
  have nextVal : next.val = start.val + count.val := by scalar_tac
  exact ⟨by rw [nextVal, countEq], by simpa only [nextVal] using writes⟩

private theorem blockAdvance (length start : Nat) (hasNext : start < length)
    (aligned : start % 64 = 0) :
    let next := start + min 64 (length - start)
    start < next ∧ next ≤ length ∧ (next = length ∨ next % 64 = 0) := by
  dsimp only
  by_cases full : 64 ≤ length - start
  · rw [Nat.min_eq_left full]
    omega
  · rw [Nat.min_eq_right (by omega)]
    omega

private def streamPad (initial : State) (counter : Word) (index : Nat) : BitVec 8 :=
  serializeBytes (blockWords initial (BitVec.ofNat 32 (counter.toNat + index / 64)))
    ⟨index % 64, Nat.mod_lt _ (by decide)⟩

private def prefixEffect (initial : State) (counter : Word) (original current : SliceBytes) (offset : Nat) : Prop :=
  current.val.length = original.val.length ∧
    ∀ index, index < original.val.length →
      byteAt current index =
        if index < offset then byteAt original index ^^^ streamPad initial counter index
        else byteAt original index

private theorem extendPrefix (initial : State) (counter : Word) (original current output : SliceBytes)
    (pad : ByteArray) (start next : Nat)
    (aligned : start % 64 = 0) (monotone : start ≤ next) (inBlock : next ≤ start + 64)
    (prior : prefixEffect initial counter original current start)
    (writes : rangeEffect current output start next pad)
    (padView : byteView pad = serializeBytes (blockWords initial (BitVec.ofNat 32 (counter.toNat + start / 64)))) :
    prefixEffect initial counter original output next := by
  obtain ⟨priorSize, priorBytes⟩ := prior
  obtain ⟨nextSize, nextBytes⟩ := writes
  refine ⟨nextSize.trans priorSize, ?_⟩
  intro index inside
  rw [nextBytes index (by omega), priorBytes index inside]
  by_cases written : start ≤ index ∧ index < next
  · rw [if_pos written, if_neg (by omega), if_pos written.2]
    have block : index / 64 = start / 64 := by omega
    have offset : index % 64 = index - start := by omega
    simp only [streamPad, block]
    let padIndex : Fin 64 := ⟨index - start, by omega⟩
    have padByte := congrFun padView padIndex
    have indexEq : (⟨index % 64, Nat.mod_lt _ (by decide)⟩ : Fin 64) = padIndex := Fin.ext offset
    rw [indexEq]
    exact congrArg (byteAt original index ^^^ ·) padByte
  · rw [if_neg written]
    have unchanged : index < next ↔ index < start := by omega
    simp only [unchanged]

/-- The exact extracted outer loop advances by one block at a time. The input
length minus its offset is a decreasing measure, including a final partial block. -/
theorem source_apply_keystream_loop_refines (counter : U32) (input : SliceBytes)
    (initial : Aeneas.Std.Array U32 16#usize)
    (allowed : admissible counter.val input.val.length) :
    apply_keystream_loop counter input initial 0#usize
      ⦃ output => prefixEffect (stateView initial) counter.bv input output input.val.length ⦄ := by
  unfold apply_keystream_loop
  refine loop.spec_decr_nat
    (fun state : SliceBytes × Usize => input.val.length - state.2.val)
    (fun state => state.2.val ≤ input.val.length ∧
      (state.2.val = input.val.length ∨ state.2.val % 64 = 0) ∧
      prefixEffect (stateView initial) counter.bv input state.1 state.2.val) _ _ _ ?_ ?_
  · rintro ⟨current, offset⟩ ⟨offsetBound, alignOrEnd, effect⟩
    dsimp only at offsetBound alignOrEnd effect
    have sameLength := effect.1
    unfold apply_keystream_loop.body
    dsimp only
    by_cases run : offset < Slice.len current
    · rw [if_pos run]
      have within : offset.val < input.val.length := by scalar_tac
      have aligned : offset.val % 64 = 0 := alignOrEnd.resolve_left (by omega)
      have exactCounter : counter.val + offset.val / 64 < 4294967296 :=
        stream_counter_in_range counter.bv allowed ⟨offset.val, within⟩
      simp only [lift, Aeneas.Std.bind_tc_ok, BLOCK_BYTES]
      step as ⟨division, divisionEq⟩
      have divisionVal : division.val = offset.val / 64 := by scalar_tac
      have castVal : (UScalar.cast .U32 division).val = offset.val / 64 := by
        rw [UScalar.cast_val_eq, divisionVal]
        apply Nat.mod_eq_of_lt
        change offset.val / 64 < 4294967296
        omega
      step as ⟨blockCounter, counterEq⟩
      have counterVal : blockCounter.val = counter.val + offset.val / 64 := by omega
      have counterWord : blockCounter.bv = BitVec.ofNat 32 (counter.val + offset.val / 64) := by
        apply BitVec.eq_of_toNat_eq
        change blockCounter.val = (BitVec.ofNat 32 (counter.val + offset.val / 64)).toNat
        rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt exactCounter, counterVal]
      obtain ⟨pad, padResult, padView⟩ := block_refines initial blockCounter
      rw [padResult]
      simp only [Aeneas.Std.bind_tc_ok]
      have notPastEnd : offset.val ≤ current.val.length := by omega
      step with (source_xor_block_refines current offset pad notPastEnd)
        as ⟨next, updated, nextEq, writes⟩
      have active : offset.val < current.val.length := by omega
      have advance := blockAdvance current.val.length offset.val active aligned
      dsimp only at advance
      rw [← nextEq] at advance
      have countBound := Nat.min_le_left 64 (current.val.length - offset.val)
      have oneBlock : next.val ≤ offset.val + 64 := by omega
      have expectedPad : byteView pad = serializeBytes (blockWords (stateView initial)
          (BitVec.ofNat 32 (counter.val + offset.val / 64))) := by
        exact padView.trans (by rw [counterWord])
      refine ⟨by omega, ?_, ?_, by omega⟩
      · exact advance.2.2.imp (fun ended => ended.trans sameLength) id
      · exact extendPrefix (stateView initial) counter.bv input current updated pad
          offset.val next.val aligned advance.1.le oneBlock effect writes expectedPad
    · rw [if_neg run]
      simp only [WP.spec_ok]
      have finished : offset.val = input.val.length := by scalar_tac
      simpa only [← finished] using effect
  · simp [prefixEffect]

/-- The exact extracted public API returns counter exhaustion before the first
write, with the input slice itself intact. -/
theorem source_apply_keystream_rejects (key : Aeneas.Std.Array U8 32#usize)
    (nonce : Aeneas.Std.Array U8 12#usize) (counter : U32) (input : SliceBytes)
    (exhausted : ¬ admissible counter.val input.val.length) :
    apply_keystream key nonce counter input
      ⦃ output => output = (core.result.Result.Err (), input) ⦄ := by
  unfold apply_keystream
  step with (source_counter_exhausted_refines (Slice.len input) counter) as ⟨rejected, rejectedEq⟩
  have outside : counterDomain - counter.val < blockCount input.val.length := by
    simpa [admissible] using exhausted
  have reject : rejected = true := by
    simpa [outside] using rejectedEq
  simp [reject, WP.spec_ok]

/-- The exact public API terminates on every admitted slice. It returns success
and produces the RFC stream at every byte offset, with unchanged slice length. -/
theorem source_apply_keystream_accepts (key : Aeneas.Std.Array U8 32#usize)
    (nonce : Aeneas.Std.Array U8 12#usize) (counter : U32) (input : SliceBytes)
    (allowed : admissible counter.val input.val.length) :
    apply_keystream key nonce counter input
      ⦃ output => output.1 = core.result.Result.Ok () ∧ output.2.val.length = input.val.length ∧
        ∀ index, index < input.val.length →
          byteAt output.2 index = byteAt input index ^^^
            streamPad (initialFromBytes (byteView key) (byteView nonce)) counter.bv index ⦄ := by
  unfold apply_keystream
  step with (source_counter_exhausted_refines (Slice.len input) counter) as ⟨rejected, rejectedEq⟩
  have within : ¬ counterDomain - counter.val < blockCount input.val.length := by
    simpa [admissible] using allowed
  have accept : rejected = false := by
    simpa [within] using rejectedEq
  rw [accept]
  simp only [Bool.false_eq_true, if_false]
  obtain ⟨initial, initialResult, initialView⟩ := initial_state_refines key nonce
  rw [initialResult]
  simp only [Aeneas.Std.bind_tc_ok]
  step with (source_apply_keystream_loop_refines counter input initial allowed)
    as ⟨updated, effect⟩
  obtain ⟨size, writes⟩ := effect
  refine ⟨size, ?_⟩
  intro index inside
  rw [writes index inside, if_pos inside, initialView]

private def sliceView (input : SliceBytes) : Bytes input.val.length :=
  fun index => byteAt input index.val

/-- Total functional refinement of the extracted public ChaCha20 stream API.
The typed inputs fix the key and nonce widths. The result agrees with the RFC
stream formula and its explicit counter-exhaustion policy for all input bytes. -/
theorem source_apply_keystream_refines (key : Aeneas.Std.Array U8 32#usize)
    (nonce : Aeneas.Std.Array U8 12#usize) (counter : U32) (input : SliceBytes) :
    let expected := streamTransform (byteView key) (byteView nonce) counter.bv (sliceView input)
    apply_keystream key nonce counter input
      ⦃ output =>
        output.2.val.length = input.val.length ∧
        output.1 = (if expected.1 then core.result.Result.Ok () else core.result.Result.Err ()) ∧
        ∀ index : Fin input.val.length, byteAt output.2 index.val = expected.2 index ⦄ := by
  dsimp only
  have counterBound : counter.val < counterDomain := by
    change counter.val < 4294967296
    scalar_tac
  have sumGuard : counter.bv.toNat + blockCount input.val.length ≤ counterDomain ↔
      admissible counter.val input.val.length := by
    change counter.val + blockCount input.val.length ≤ counterDomain ↔
      admissible counter.val input.val.length
    unfold admissible
    omega
  by_cases allowed : admissible counter.val input.val.length
  · have fits : counter.val + blockCount input.val.length ≤ counterDomain := sumGuard.mpr allowed
    refine WP.spec_mono (source_apply_keystream_accepts key nonce counter input allowed) ?_
    intro output result
    obtain ⟨accepted, sameLength, bytes⟩ := result
    refine ⟨sameLength, ?_, ?_⟩
    · simp [streamTransform, fits, accepted]
    · intro index
      simpa [streamTransform, fits, streamPad, blockBytes, sliceView] using bytes index.val index.isLt
  · have exhausted : ¬ counter.val + blockCount input.val.length ≤ counterDomain :=
      mt sumGuard.mp allowed
    refine WP.spec_mono (source_apply_keystream_rejects key nonce counter input allowed) ?_
    intro output result
    subst output
    refine ⟨rfl, ?_, ?_⟩
    · simp [streamTransform, exhausted]
    · simp [streamTransform, exhausted, sliceView]

#print axioms source_counter_exhausted_refines
#print axioms source_xor_byte_refines
#print axioms source_xor_block_loop_refines
#print axioms source_xor_block_refines
#print axioms source_apply_keystream_loop_refines
#print axioms source_apply_keystream_rejects
#print axioms source_apply_keystream_accepts
#print axioms source_apply_keystream_refines

end Abc.Refine.ChaCha20
