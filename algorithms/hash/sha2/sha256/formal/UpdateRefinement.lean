import CounterRefinement
import ExtractedCompression
import ModelView
import Abc.Sha256.Extracted.Funs

open Aeneas Aeneas.Std
open Aeneas.Std.Result Aeneas.Std.ControlFlow

namespace Abc.Refine.Sha256.Implementation

open Abc.Spec.Sha256

set_option maxHeartbeats 1500000

private abbrev ByteArray := Aeneas.Std.Array U8 64#usize
private abbrev WordArray := Aeneas.Std.Array U32 8#usize

private theorem allowed_counter_bound (bytes : Nat) (allowed : byteLengthAllowed bytes) :
    bytes ≤ 2305843009213693951 := by
  change 8 * bytes < 18446744073709551616 at allowed
  omega

private theorem incoming_fits_pointer (input : Slice U8) :
    input.val.length % 2 ^ System.Platform.numBits = input.val.length := by
  apply Nat.mod_eq_of_lt
  simpa [UScalarTy.numBits] using (Slice.len input).hBounds

/-- The exact extracted update returns the same Rust state on length rejection. -/
theorem update_rejects_exact (state : Abc.Sha256.Extracted.Sha256) (input : Slice U8)
    (reachableLength : byteLengthAllowed state.length.val)
    (tooLong : ¬ byteLengthAllowed (state.length.val + input.val.length)) :
    Abc.Sha256.Extracted.Sha256.update state input
      ⦃ output => output = (core.result.Result.Err (), state) ⦄ := by
  have priorBound := allowed_counter_bound _ reachableLength
  change ¬ 8 * (state.length.val + input.val.length) < 18446744073709551616 at tooLong
  unfold Abc.Sha256.Extracted.Sha256.update
  simp [lift, update_maximum_eq, incoming_fits_pointer]
  step as ⟨room, room_eq⟩
  have exceeds : room.val < input.val.length := by omega
  simp [exceeds, WP.spec_ok]

private theorem take_after_set {α : Type} (values : List α) (i : Nat) (value : α)
    (inside : i < values.length) :
    (values.set i value).take (i + 1) = values.take i ++ [value] := by
  induction values generalizing i with
  | nil => simp at inside
  | cons first rest smaller =>
    cases i with
    | zero => simp
    | succ i =>
      have less : i < rest.length := by simpa using inside
      simp [List.set, smaller i less]

/-- The extracted tail-copy loop records precisely the uncompressed slice. -/
theorem update_tail_loop_refines (storage : ByteArray) (input : Slice U8)
    (short : input.val.length < 64) :
    Abc.Sha256.Extracted.Sha256.update_loop2 storage 0#usize input
      ⦃ result => result.2.val = input.val.length ∧ result.1.val.take result.2.val = input.val ⦄ := by
  unfold Abc.Sha256.Extracted.Sha256.update_loop2
  refine loop.spec_decr_nat
    (fun pair : ByteArray × Usize => input.val.length - pair.2.val)
    (fun pair => pair.2.val ≤ input.val.length ∧
      pair.1.val.take pair.2.val = input.val.take pair.2.val)
    _ _ _ ?_ ?_
  · rintro ⟨array, i⟩ ⟨before, prefixEq⟩
    dsimp only at before prefixEq
    unfold Abc.Sha256.Extracted.Sha256.update_loop2.body
    dsimp only
    by_cases less : i.val < input.val.length
    · have guard : i < Slice.len input := by scalar_tac
      rw [if_pos guard]
      have arrayBound : i.val < array.val.length := by scalar_tac
      step as ⟨value, value_eq⟩
      step as ⟨updated, updated_eq⟩
      step as ⟨next, next_eq⟩
      have nextNat : next.val = i.val + 1 := by scalar_tac
      refine ⟨by omega, ?_, ?_⟩
      · rw [nextNat, updated_eq, Array.set_val_eq, take_after_set _ _ _ arrayBound, prefixEq, value_eq,
          List.take_succ_eq_append_getElem less]
      · omega
    · have guard : ¬ i < Slice.len input := by scalar_tac
      rw [if_neg guard]
      simp only [WP.spec_ok]
      have equal : i.val = input.val.length := by omega
      exact ⟨equal, by simpa [equal] using prefixEq⟩
  · simp

theorem update_tail_loop4_eq (storage : ByteArray) (offset : Usize) (input : Slice U8) :
    Abc.Sha256.Extracted.Sha256.update_loop4 storage offset input =
      Abc.Sha256.Extracted.Sha256.update_loop2 storage offset input := by
  rfl

/-- The extracted first loop fills the remaining space in a previously pending block. -/
theorem update_fill_loop_refines (storage : ByteArray) (start : Usize) (input : Slice U8)
    (startBound : start.val ≤ 64) :
    Abc.Sha256.Extracted.Sha256.update_loop0 storage start input 0#usize
      ⦃ result => result.2.2.val = min (64 - start.val) input.val.length ∧
        result.2.1.val = start.val + result.2.2.val ∧
        result.1.val.take result.2.1.val =
          storage.val.take start.val ++ input.val.take result.2.2.val ⦄ := by
  unfold Abc.Sha256.Extracted.Sha256.update_loop0
  refine loop.spec_decr_nat
    (fun triple : ByteArray × Usize × Usize => 64 - triple.2.1.val)
    (fun triple => triple.2.1.val ≤ 64 ∧ triple.2.2.val ≤ input.val.length ∧
      triple.2.1.val = start.val + triple.2.2.val ∧
      triple.1.val.take triple.2.1.val =
        storage.val.take start.val ++ input.val.take triple.2.2.val)
    _ _ _ ?_ ?_
  · rintro ⟨array, i, copied⟩ ⟨room, before, counter, prefixEq⟩
    dsimp only at room before counter prefixEq
    unfold Abc.Sha256.Extracted.Sha256.update_loop0.body
    dsimp only
    by_cases space : i.val < 64
    · have blockGuard : i < Abc.Sha256.Extracted.BLOCK_BYTES := by
        simp [Abc.Sha256.Extracted.BLOCK_BYTES]; scalar_tac
      rw [if_pos blockGuard]
      by_cases remaining : copied.val < input.val.length
      · have inputGuard : copied < Slice.len input := by scalar_tac
        rw [if_pos inputGuard]
        have arrayBound : i.val < array.val.length := by scalar_tac
        step as ⟨value, value_eq⟩
        step as ⟨updated, updated_eq⟩
        step as ⟨next, next_eq⟩
        step as ⟨nextCopy, nextCopy_eq⟩
        have nextNat : next.val = i.val + 1 := by scalar_tac
        have nextCopyNat : nextCopy.val = copied.val + 1 := by scalar_tac
        refine ⟨by omega, by omega, by omega, ?_, ?_⟩
        · rw [nextNat, nextCopyNat, updated_eq, Array.set_val_eq, take_after_set _ _ _ arrayBound,
            prefixEq, value_eq, List.take_succ_eq_append_getElem remaining, List.append_assoc]
        · omega
      · have inputGuard : ¬ copied < Slice.len input := by scalar_tac
        rw [if_neg inputGuard]
        simp only [WP.spec_ok]
        refine ⟨?_, counter, prefixEq⟩
        rw [Nat.min_eq_right (by omega)]
        omega
    · have blockGuard : ¬ i < Abc.Sha256.Extracted.BLOCK_BYTES := by
        simp [Abc.Sha256.Extracted.BLOCK_BYTES]; scalar_tac
      rw [if_neg blockGuard]
      simp only [WP.spec_ok]
      refine ⟨?_, counter, prefixEq⟩
      rw [Nat.min_eq_left (by omega)]
      omega
  · simp [startBound]

def CompressesAsSpec : Prop :=
  ∀ (state : WordArray) (block : Slice U8), block.val.length = 64 →
    Abc.Sha256.Extracted.compress state block
      ⦃ output => stateView output = compress (stateView state) (bytesView block.val) ⦄

/-- Each generated bulk-loop iteration consumes one full block in input order. -/
theorem update_bulk_loop_refines (compression : CompressesAsSpec) (state : WordArray) (input : Slice U8) :
    Abc.Sha256.Extracted.Sha256.update_loop1 state input
      ⦃ result =>
        stateView result.1 = (Streaming.splitBlocks (bytesView input.val)).1.foldl compress (stateView state) ∧
        bytesView result.2.val = (Streaming.splitBlocks (bytesView input.val)).2 ⦄ := by
  unfold Abc.Sha256.Extracted.Sha256.update_loop1
  let expected := Streaming.splitBlocks (bytesView input.val)
  refine loop.spec_decr_nat
    (fun pair : WordArray × Slice U8 => pair.2.val.length)
    (fun pair =>
      (Streaming.splitBlocks (bytesView pair.2.val)).1.foldl compress (stateView pair.1) =
        expected.1.foldl compress (stateView state) ∧
      (Streaming.splitBlocks (bytesView pair.2.val)).2 = expected.2)
    _ _ _ ?_ ?_
  · rintro ⟨registers, remaining⟩ ⟨registerEq, tailEq⟩
    unfold Abc.Sha256.Extracted.Sha256.update_loop1.body
    dsimp only
    by_cases short : remaining.val.length < 64
    · have guard : ¬ Slice.len remaining ≥ Abc.Sha256.Extracted.BLOCK_BYTES := by
        simp [Abc.Sha256.Extracted.BLOCK_BYTES]; scalar_tac
      rw [if_neg guard]
      have byteShort : (bytesView remaining.val).length < 64 := by simpa using short
      rw [Streaming.splitBlocks, if_pos byteShort] at registerEq tailEq
      simpa only [WP.spec_ok, Prod.fst, Prod.snd, List.foldl_nil] using And.intro registerEq tailEq
    · have guard : Slice.len remaining ≥ Abc.Sha256.Extracted.BLOCK_BYTES := by
        simp [Abc.Sha256.Extracted.BLOCK_BYTES]; scalar_tac
      rw [if_pos guard]
      step as ⟨block, headSlice, headLength⟩
      have blockSize : block.val.length = 64 := by
        simpa [Abc.Sha256.Extracted.BLOCK_BYTES, Slice.length] using headLength
      step with (compression registers block blockSize) as ⟨next, next_eq⟩
      step as ⟨tail, tailSlice, tailLength⟩
      have bytesLong : ¬ (bytesView remaining.val).length < 64 := by simpa using short
      rw [Streaming.splitBlocks, if_neg bytesLong] at registerEq tailEq
      have blockBytes : bytesView block.val = (bytesView remaining.val).take 64 := by
        simp [headSlice, List.slice, Abc.Sha256.Extracted.BLOCK_BYTES]
      have residualBytes : bytesView tail.val = (bytesView remaining.val).drop 64 := by
        simp [tailSlice, Abc.Sha256.Extracted.BLOCK_BYTES]
      refine ⟨?_, ?_, ?_⟩
      · simpa [residualBytes, next_eq, blockBytes] using registerEq
      · simpa [residualBytes] using tailEq
      · rw [tailSlice, List.length_drop]
        simp [Abc.Sha256.Extracted.BLOCK_BYTES]
        omega
  · exact ⟨rfl, rfl⟩

theorem update_bulk_loop3_eq (state : WordArray) (input : Slice U8) :
    Abc.Sha256.Extracted.Sha256.update_loop3 state input =
      Abc.Sha256.Extracted.Sha256.update_loop1 state input := by
  rfl

private theorem short_split_tail (original : Message) (tail : Slice U8)
    (equal : bytesView tail.val = (Streaming.splitBlocks original).2) :
    tail.val.length < 64 := by
  have short := (Streaming.splitBlocks_partition original).short
  rwa [← equal, bytesView_length] at short

/-- The exact extracted update preserves the independent model on successful calls. -/
theorem update_accepts_exact (compression : CompressesAsSpec)
    (state : Abc.Sha256.Extracted.Sha256) (input : Slice U8)
    (bufferBound : state.buffered.val < 64)
    (allowed : byteLengthAllowed (state.length.val + input.val.length)) :
    Abc.Sha256.Extracted.Sha256.update state input
      ⦃ output => output.1 = core.result.Result.Ok () ∧
        streamView output.2 = (Streaming.update compress (streamView state) (bytesView input.val)).2 ⦄ := by
  have priorAllowed : byteLengthAllowed state.length.val := by
    change 8 * state.length.val < 18446744073709551616
    change 8 * (state.length.val + input.val.length) < 18446744073709551616 at allowed
    omega
  have priorBound := allowed_counter_bound _ priorAllowed
  have totalBound := allowed_counter_bound _ allowed
  have blockLength : state.block.val.length = 64 := by scalar_tac
  have pendingLength : (streamView state).pending.length = state.buffered.val := by
    simp [streamView, List.length_take, blockLength, Nat.min_eq_left (Nat.le_of_lt bufferBound)]
  have counter : Streaming.checkedLength (streamView state).length (bytesView input.val).length =
      some (state.length.val + input.val.length) := by
    simp [streamView, Streaming.checkedLength_matches_domain _ _ priorAllowed, allowed]
  simp only [Streaming.update, counter]
  unfold Abc.Sha256.Extracted.Sha256.update
  simp [lift, update_maximum_eq, incoming_fits_pointer]
  step as ⟨room, room_eq⟩
  have within : ¬ room.val < input.val.length := by omega
  rw [if_neg within]
  step as ⟨total, total_eq⟩
  have totalNat : total.val = state.length.val + input.val.length := by
    simpa [update_cast_length] using total_eq
  by_cases emptyBuffer : state.buffered = 0#usize
  · simp [emptyBuffer, update_bulk_loop3_eq]
    step with (update_bulk_loop_refines compression) as ⟨folded, tail, folded_eq, tail_eq⟩
    have tailShort := short_split_tail (bytesView input.val) tail tail_eq
    rw [update_tail_loop4_eq]
    step with update_tail_loop_refines as ⟨buffer, buffered, buffered_eq, buffer_eq⟩
    have noPending : (streamView state).pending = [] := by simp [streamView, emptyBuffer, bytesView]
    rw [noPending]
    simp [streamView, folded_eq, buffer_eq, tail_eq, totalNat]
  · have bufferNonzero : state.buffered.val ≠ 0 := by simpa using emptyBuffer
    simp only [if_neg bufferNonzero]
    step with update_fill_loop_refines as
      ⟨filled, fillIndex, copied, copied_eq, fill_eq, prefix_eq⟩
    have fitsSpace : copied.val ≤ 64 - state.buffered.val := by
      rw [copied_eq]
      exact Nat.min_le_left ..
    have fitsInput : copied.val ≤ input.val.length := by
      rw [copied_eq]
      exact Nat.min_le_right ..
    have copyCount : copied.val = min (64 - (streamView state).pending.length) (bytesView input.val).length := by
      simpa [pendingLength] using copied_eq
    have fillPrefix : bytesView (filled.val.take fillIndex.val) =
        (streamView state).pending ++ (bytesView input.val).take copied.val := by
      simp [prefix_eq, streamView]
    by_cases incomplete : fillIndex.val < 64
    · have guard : fillIndex.val < Abc.Sha256.Extracted.BLOCK_BYTES.val := by
        simpa [Abc.Sha256.Extracted.BLOCK_BYTES] using incomplete
      rw [if_pos guard]
      have inputShort : input.val.length < 64 - state.buffered.val := by
        by_contra no
        have copyFills : copied.val = 64 - state.buffered.val := by
          rw [copied_eq, Nat.min_eq_left (by omega)]
        omega
      have splitShort := Streaming.fill_buffer_short (streamView state).pending (bytesView input.val)
        (by simpa [pendingLength] using bufferBound) (by simpa [pendingLength] using inputShort)
      rw [splitShort, ← copyCount]
      simp [WP.spec_ok, streamView, totalNat]
      simpa [streamView] using fillPrefix
    · have guard : ¬ fillIndex.val < Abc.Sha256.Extracted.BLOCK_BYTES.val := by
        simpa [Abc.Sha256.Extracted.BLOCK_BYTES] using incomplete
      rw [if_neg guard]
      have filledSize : filled.val.length = 64 := by scalar_tac
      have full : fillIndex.val = 64 := by omega
      have copyFills : copied.val = 64 - (streamView state).pending.length := by
        rw [pendingLength]
        omega
      have blockBytes :
          bytesView filled.val =
            (streamView state).pending ++ (bytesView input.val).take (64 - (streamView state).pending.length) := by
        have all : filled.val.take fillIndex.val = filled.val := List.take_of_length_le (by omega)
        simpa [all, copyFills] using fillPrefix
      have sliceSize : (Array.to_slice filled).val.length = 64 := by simp
      step with (compression state.state (Array.to_slice filled) sliceSize) as ⟨compressed, compressed_eq⟩
      step as ⟨rest, rest_eq, rest_length⟩
      step with (update_bulk_loop_refines compression) as ⟨folded, tail, folded_eq, tail_eq⟩
      have tailShort := short_split_tail (bytesView rest.val) tail tail_eq
      step with update_tail_loop_refines as ⟨buffer, buffered, buffered_eq, buffer_eq⟩
      have splitFull := Streaming.fill_buffer_full (streamView state).pending (bytesView input.val)
        (by simpa [pendingLength] using bufferBound) (by simpa [← copyFills] using fitsInput)
      have restBytes : bytesView rest.val =
          (bytesView input.val).drop (64 - (streamView state).pending.length) := by
        simp [rest_eq, copyFills]
      rw [splitFull]
      simp [streamView, folded_eq, compressed_eq, blockBytes, restBytes,
        buffer_eq, tail_eq, totalNat]

/-- The complete extracted update specifies both the successful transition and the unchanged error state. -/
theorem update_refines_under_compression (compression : CompressesAsSpec)
    (state : Abc.Sha256.Extracted.Sha256) (message : Message) (input : Slice U8)
    (representation : Streaming.Represents initial compress (streamView state) message) :
    Abc.Sha256.Extracted.Sha256.update state input
      ⦃ output =>
        if byteLengthAllowed (message.length + (bytesView input.val).length) then
          output.1 = core.result.Result.Ok () ∧ Streaming.Represents initial compress (streamView output.2)
            (message ++ bytesView input.val)
        else output = (core.result.Result.Err (), state) ⦄ := by
  have ⟨blocks, partition, lengthEq, priorAllowed, foldEq⟩ := representation
  have priorEq : state.length.val = message.length := lengthEq
  have priorCounterAllowed : byteLengthAllowed state.length.val := by simpa [priorEq] using priorAllowed
  by_cases allowed : byteLengthAllowed (message.length + (bytesView input.val).length)
  · simp only [if_pos allowed]
    have arrayLength : state.block.val.length = 64 := by scalar_tac
    have bufferBound : state.buffered.val < 64 := by
      have short := partition.short
      simp only [streamView, bytesView_length, List.length_take, arrayLength] at short
      by_contra no
      rw [Nat.min_eq_right (by omega)] at short
      omega
    have machineAllowed : byteLengthAllowed (state.length.val + input.val.length) := by
      simpa [priorEq] using allowed
    apply WP.spec_mono (update_accepts_exact compression state input bufferBound machineAllowed)
    intro output success
    refine ⟨success.1, ?_⟩
    rw [success.2]
    exact (Streaming.update_preserves_representation representation _ allowed).2
  · simp only [if_neg allowed]
    exact update_rejects_exact state input priorCounterAllowed (by simpa [priorEq] using allowed)

/-- The extracted Rust update refines a streaming step over the standard SHA-256 compression function. -/
theorem update_refines
    (state : Abc.Sha256.Extracted.Sha256) (message : Message) (input : Slice U8)
    (representation : Streaming.Represents initial compress (streamView state) message) :
    Abc.Sha256.Extracted.Sha256.update state input
      ⦃ output =>
        if byteLengthAllowed (message.length + (bytesView input.val).length) then
          output.1 = core.result.Result.Ok () ∧ Streaming.Represents initial compress (streamView output.2)
            (message ++ bytesView input.val)
        else output = (core.result.Result.Err (), state) ⦄ := by
  apply update_refines_under_compression _ state message input representation
  intro registers block length
  exact (WP.spec_equiv_exists _ _).mpr (compress_refines registers block length)

end Abc.Refine.Sha256.Implementation
