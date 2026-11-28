import Poly1305ApiRefinement

namespace Abc.Refine.Poly1305.Stream

open Aeneas Aeneas.Std Result ControlFlow
open Abc.Poly1305.Extracted
open Abc.Refine.Poly1305 (columns cachedMultiples)
open Abc.Refine.Poly1305.Bytes (blockValue source_absorb_full_block_refines)
open Abc.Refine.Poly1305.Api (Ready clamp finalResidue source_new_refines source_finalize_refines)
open Abc.Spec.Poly1305.Go (base bounded live value modulus)
open Abc.Foundation (decodeLittleEndian)

set_option maxHeartbeats 4500000
set_option maxRecDepth 4096

private abbrev Words := Aeneas.Std.Array U64 5#usize
private abbrev Multiples := Aeneas.Std.Array U64 4#usize
private abbrev Block := Aeneas.Std.Array U8 16#usize

/-- One unbounded RFC 8439 step on a complete or final partial message block. -/
def blockStep (r h : Nat) (message : List U8) : Nat :=
  ((h + decodeLittleEndian (message.map U8.bv) + 256^message.length) * r) % modulus

/-- Consume complete blocks in order and retain the unprocessed final suffix. -/
def blocks (r h : Nat) (message : List U8) : Nat × List U8 :=
  if message.length < 16 then (h, message)
  else blocks r (blockStep r h (message.take 16)) (message.drop 16)
termination_by message.length
decreasing_by simp; omega

theorem blocks_tail_short (r h : Nat) (message : List U8) : (blocks r h message).2.length < 16 := by
  rw [blocks]
  split
  next short => exact short
  next => exact blocks_tail_short r _ _
termination_by message.length
decreasing_by simp; omega

/-- The mathematical computation is invariant under an arbitrary chunk boundary. -/
theorem blocks_append (r h : Nat) (previous incoming : List U8) :
    blocks r h (previous ++ incoming) =
      blocks r (blocks r h previous).1 ((blocks r h previous).2 ++ incoming) := by
  by_cases short : previous.length < 16
  · rw [blocks.eq_def r h previous, if_pos short]
  · have enough : 16 ≤ previous.length := by omega
    have combined : ¬ (previous ++ incoming).length < 16 := by simp; omega
    rw [blocks.eq_def r h previous, if_neg short, blocks.eq_def r h (previous ++ incoming), if_neg combined,
      List.take_append_of_le_length enough, List.drop_append_of_le_length enough]
    exact blocks_append r _ _ _
termination_by previous.length
decreasing_by simp; omega

private theorem feed_short (r h : Nat) (pending incoming : List U8)
    (fits : pending.length + incoming.length < 16) :
    blocks r h (pending ++ incoming) = (h, pending ++ incoming) := by
  rw [blocks, if_pos (by simpa only [List.length_append] using fits)]

private theorem feed_full (r h : Nat) (pending incoming : List U8)
    (within : pending.length < 16) (enough : 16 ≤ pending.length + incoming.length) :
    blocks r h (pending ++ incoming) =
      blocks r (blockStep r h (pending ++ incoming.take (16 - pending.length)))
        (incoming.drop (16 - pending.length)) := by
  have full : ¬ (pending ++ incoming).length < 16 := by simp; omega
  have takePending : pending.take 16 = pending := List.take_of_length_le (by omega)
  have dropPending : pending.drop 16 = [] := List.drop_eq_nil_of_le (by omega)
  rw [blocks.eq_def r h (pending ++ incoming), if_neg full, List.take_append, List.drop_append,
    takePending, dropPending, List.nil_append]

def pendingBytes (state : Poly1305) : List U8 := state.pending.val.take state.buffered.val

def stateField (state : Poly1305) : Nat := value (columns state.h) % modulus

def stateMultiplier (state : Poly1305) : Nat := value (columns state.r)

def commitTail (r h : Nat) (pending : List U8) : Nat :=
  if pending.isEmpty then h else blockStep r h pending

/-- The RFC tag as a little-endian integer for an arbitrary complete message. -/
def authenticateInteger (key message : List U8) : Nat :=
  let r := clamp ((key.take 16).map U8.bv)
  let pad := decodeLittleEndian ((key.drop 16).map U8.bv)
  let state := blocks r 0 message
  (commitTail r state.1 state.2 + pad) % 2^128

private theorem pending_length (state : Poly1305) (ready : Ready state) :
    (pendingBytes state).length = state.buffered.val := by
  have length : state.pending.val.length = 16 := by simp
  simp only [pendingBytes, List.length_take, length, Nat.min_eq_left (Nat.le_of_lt ready.pendingFits)]

private theorem final_residue_eq (state : Poly1305) (ready : Ready state) :
    finalResidue state = commitTail (stateMultiplier state) (stateField state) (pendingBytes state) := by
  have pendingLen := pending_length state ready
  by_cases zero : state.buffered.val = 0
  · have empty : pendingBytes state = [] := List.length_eq_zero_iff.mp (pendingLen.trans zero)
    simp [finalResidue, zero, commitTail, empty, stateField]
  · have existsByte : ¬ pendingBytes state = [] := by
      intro empty
      apply zero
      simpa only [empty, List.length_nil] using pendingLen.symm
    have nonempty : (pendingBytes state).isEmpty = false := by simp [existsByte]
    unfold finalResidue commitTail
    rw [if_neg zero, nonempty]
    simp only [Bool.false_eq_true, if_false, blockStep, stateMultiplier, stateField, pendingLen]
    simp only [pendingBytes, List.map_take]

/-- Observable effect of updating a ready state with one input chunk. -/
def UpdateEffect (before after : Poly1305) (input : List U8) : Prop :=
  Ready after ∧ after.r = before.r ∧ after.r_times_five = before.r_times_five ∧
    after.pad = before.pad ∧ (stateField after, pendingBytes after) =
      blocks (stateMultiplier before) (stateField before) (pendingBytes before ++ input)

private theorem block_step_source (h r : Words) (cache : Multiples) (message : Block)
    (hLive : live (columns h)) (rFits : bounded (columns r) base) (cached : cachedMultiples r cache) :
    absorb_bytes h r cache message 16777216#u64 ⦃ out => live (columns out) ∧
      value (columns out) % modulus = blockStep (value (columns r)) (value (columns h) % modulus) message.val ⦄ := by
  refine WP.spec_mono (source_absorb_full_block_refines h r cache message hLive rFits cached) ?_
  intro out proof
  have length : message.val.length = 16 := by simp
  simpa only [blockStep, blockValue, length, show 256^16 = 2^128 by decide] using proof

private theorem full_marker : (1#u64 <<< 24#i32) = .ok 16777216#u64 := by rfl

private theorem block_bytes : BLOCK_BYTES.val = 16 := by rw [BLOCK_BYTES]; decide

private theorem overwrite_prefix (old new : List U8) (offset : Nat)
    (fits : offset + new.length ≤ old.length) :
    (old.setSlice! offset new).take (offset + new.length) = old.take offset ++ new := by
  rw [List.setSlice!, Nat.min_eq_left (by omega), List.take_length]
  have written : (old.take offset ++ new).length = offset + new.length := by
    simp [Nat.min_eq_left (show offset ≤ old.length by omega)]
  rw [List.append_assoc, ← List.append_assoc (old.take offset), ← written, List.take_append_length]

/-- The actual range copy preserves the preceding logical bytes and writes
the whole incoming slice immediately after them. -/
theorem source_copy_pending_refines (old : Block) (offset : Usize) (input : Slice U8)
    (fits : offset.val + input.val.length ≤ 16) :
    copy_pending old offset input ⦃ out => out.val.take (offset.val + input.val.length) =
      old.val.take offset.val ++ input.val ⦄ := by
  unfold copy_pending
  step as ⟨stop, stopEq⟩
  have offsetBefore : offset ≤ stop := by scalar_tac
  have offsetEnd : stop ≤ BLOCK_BYTES := by simp [BLOCK_BYTES]; scalar_tac
  step as ⟨region, back, regionEq, regionLen, backEq⟩
  have copyLength : region.length = input.length := by scalar_tac
  step as ⟨copied, copiedEq⟩
  rw [backEq, copiedEq]
  exact overwrite_prefix _ _ _ (by scalar_tac)

/-- The actual bulk loop consumes all complete blocks and returns the
short input suffix unchanged, with a live resulting accumulator. -/
theorem source_absorb_blocks_refines (h r : Words) (cache : Multiples) (input : Slice U8)
    (hLive : live (columns h)) (rFits : bounded (columns r) base) (cached : cachedMultiples r cache) :
    absorb_blocks h r cache input ⦃ out tail => live (columns out) ∧
      (value (columns out) % modulus, tail.val) = blocks (value (columns r)) (value (columns h) % modulus) input.val ⦄ := by
  unfold absorb_blocks absorb_blocks_loop
  refine loop.spec_decr_nat
    (fun pair : Words × Slice U8 => pair.2.val.length)
    (fun pair => live (columns pair.1) ∧
      blocks (value (columns r)) (value (columns pair.1) % modulus) pair.2.val =
        blocks (value (columns r)) (value (columns h) % modulus) input.val) _ _ _ ?_ ?_
  · rintro ⟨accum, remaining⟩ ⟨accumLive, loopEq⟩
    unfold absorb_blocks_loop.body
    dsimp only
    by_cases short : remaining.val.length < 16
    · have guard : ¬ Slice.len remaining ≥ BLOCK_BYTES := by simp [BLOCK_BYTES]; scalar_tac
      rw [if_neg guard]
      have stopped := loopEq
      rw [blocks.eq_def, if_pos short] at stopped
      simpa only [WP.spec_ok, WP.uncurry'] using And.intro accumLive stopped
    · have guard : Slice.len remaining ≥ BLOCK_BYTES := by simp [BLOCK_BYTES]; scalar_tac
      rw [if_pos guard]
      step as ⟨front, frontEq, frontLen⟩
      step as ⟨converted, convertedEq⟩
      cases converted with
      | Err err =>
        cases err
        exact False.elim (convertedEq (by simpa only [BLOCK_BYTES, show (16#usize).val = 16 by decide] using frontLen))
      | Ok message =>
        obtain ⟨messageEq, messageLen⟩ := convertedEq
        simp only [full_marker, Aeneas.Std.bind_tc_ok]
        step with block_step_source accum r cache message accumLive rFits cached as ⟨new, newLive, newEq⟩
        step as ⟨tail, tailEq, tailLen⟩
        have exactBlock : message.val = remaining.val.take 16 := by
          simp [messageEq, frontEq, List.slice, BLOCK_BYTES]
        have exactTail : tail.val = remaining.val.drop 16 := by simp [tailEq, BLOCK_BYTES]
        have expected := loopEq
        rw [blocks.eq_def (value (columns r)) (value (columns accum) % modulus) remaining.val,
          if_neg short] at expected
        refine ⟨newLive, ?_, ?_⟩
        · simpa only [exactTail, newEq, exactBlock] using expected
        · rw [exactTail, List.length_drop]
          omega
  · exact ⟨hLive, rfl⟩

private theorem source_drain_and_save (state : Poly1305) (h : Words) (pending : Block) (input : Slice U8)
    (hLive : live (columns h)) (ready : Ready state) :
    (do
      let (out, tail) ← absorb_blocks h state.r state.r_times_five input
      let stored ← copy_pending pending 0#usize tail
      .ok { state with h := out, pending := stored, buffered := Slice.len tail }) ⦃ out =>
        Ready out ∧ out.r = state.r ∧ out.r_times_five = state.r_times_five ∧ out.pad = state.pad ∧
          (stateField out, pendingBytes out) =
            blocks (stateMultiplier state) (value (columns h) % modulus) input.val ⦄ := by
  step with (source_absorb_blocks_refines h state.r state.r_times_five input hLive ready.keyFits ready.keyCache)
    as ⟨out, tail, outLive, processed⟩
  have tailEq := congrArg Prod.snd processed
  have tailFits : tail.val.length < 16 := by
    rw [show tail.val = (blocks (value (columns state.r)) (value (columns h) % modulus) input.val).2 from tailEq]
    exact blocks_tail_short _ _ _
  have copyFits : (0#usize).val + tail.val.length ≤ 16 := by scalar_tac
  step with (source_copy_pending_refines pending 0#usize tail copyFits) as ⟨stored, storedEq⟩
  have count : (Slice.len tail).val = tail.val.length := by simp
  simp only [Nat.zero_add, List.take_zero, List.nil_append] at storedEq
  refine ⟨⟨ready.keyFits, ready.keyCache, outLive, by rwa [count]⟩, ?_⟩
  simp only [stateField, pendingBytes, count, storedEq, stateMultiplier]
  exact processed

/-- The exact public update refines the RFC recurrence on the old logical
suffix followed by the incoming bytes, keeping the original key and pad. -/
theorem source_update_refines (state : Poly1305) (input : Slice U8) (ready : Ready state) :
    Poly1305.update state input ⦃ out => UpdateEffect state out input.val ⦄ := by
  have pendingLen := pending_length state ready
  have bufferedBound := ready.pendingFits
  unfold Poly1305.update
  by_cases empty : state.buffered = 0#usize
  · have guard : ¬ (state.buffered != 0#usize) = true := by simp [empty]
    rw [if_neg guard]
    have noPending : pendingBytes state = [] := by simp [pendingBytes, empty]
    refine WP.spec_mono (source_drain_and_save state state.h state.pending input ready.accumulatorFits ready) ?_
    intro out exactUpdate
    simpa only [UpdateEffect, stateField, noPending, List.nil_append] using exactUpdate
  · have guard : (state.buffered != 0#usize) = true := by simpa using empty
    rw [if_pos guard]
    have atMostBlock : state.buffered.val ≤ BLOCK_BYTES.val := by
      simpa only [block_bytes] using Nat.le_of_lt ready.pendingFits
    step with (UScalar.sub_spec atMostBlock) as ⟨room, roomEq⟩
    have roomSize : room.val = 16 - state.buffered.val := by simpa only [block_bytes] using roomEq
    let copied := if Slice.len input < room then Slice.len input else room
    have copiedExpr : (if Slice.len input < room then .ok (Slice.len input) else .ok room : Result Usize) = .ok copied := by
      unfold copied
      split <;> rfl
    rw [copiedExpr, Aeneas.Std.bind_tc_ok]
    have copyCount : copied.val = min input.val.length (16 - state.buffered.val) := by
      unfold copied
      split
      next before =>
        have fit : input.val.length ≤ 16 - state.buffered.val := by scalar_tac
        simp [Nat.min_eq_left fit]
      next after =>
        have fit : 16 - state.buffered.val ≤ input.val.length := by scalar_tac
        simp [roomSize, Nat.min_eq_right fit]
    have copyInput : copied.val ≤ input.val.length := by rw [copyCount]; exact Nat.min_le_left ..
    have copyRoom : copied.val ≤ 16 - state.buffered.val := by rw [copyCount]; exact Nat.min_le_right ..
    have endFits : state.buffered.val + copied.val ≤ UScalar.max .Usize := by scalar_tac
    step with (UScalar.add_spec endFits) as ⟨stop, stopEq⟩
    have stopValue : stop.val = state.buffered.val + copied.val := stopEq
    have stopFits : stop.val ≤ 16 := by rw [stopValue]; omega
    step as ⟨front, frontEq, frontBound⟩
    have exactFront : front.val = input.val.take copied.val := by
      simpa only [List.slice, List.drop_zero, Nat.sub_zero] using frontEq
    have frontLen : front.val.length = copied.val := by scalar_tac
    have within : state.buffered.val + front.val.length ≤ 16 := by rw [frontLen, ← stopValue]; exact stopFits
    step with (source_copy_pending_refines state.pending state.buffered front within) as ⟨filled, written⟩
    have prefixEq : filled.val.take stop.val = pendingBytes state ++ input.val.take copied.val := by
      have stopFront : stop.val = state.buffered.val + front.val.length := by rw [stopValue, frontLen]
      rw [stopFront, written, exactFront]
      rfl
    by_cases short : stop.val < 16
    · have guard : stop < BLOCK_BYTES := by simpa only [UScalar.lt_equiv, block_bytes] using short
      rw [if_pos guard]
      have inputShort : input.val.length < 16 - state.buffered.val := by
        by_contra longer
        have amount : copied.val = 16 - state.buffered.val := by rw [copyCount, Nat.min_eq_right (by omega)]
        omega
      have allCopied : copied.val = input.val.length := by rw [copyCount, Nat.min_eq_left (by omega)]
      have expected := feed_short (stateMultiplier state) (stateField state) (pendingBytes state) input.val (by omega)
      simp only [WP.spec_ok, UpdateEffect, expected]
      refine ⟨⟨ready.keyFits, ready.keyCache, ready.accumulatorFits, short⟩, True.intro, True.intro, True.intro, ?_⟩
      change (stateField state, filled.val.take stop.val) = _
      rw [prefixEq, allCopied, List.take_length]
    · have guard : ¬ stop < BLOCK_BYTES := by simpa only [UScalar.lt_equiv, block_bytes] using short
      rw [if_neg guard]
      have full : stop.val = 16 := by omega
      have filling : copied.val = 16 - (pendingBytes state).length := by omega
      have pendingFit : (pendingBytes state).length < 16 := by omega
      have enough : 16 ≤ (pendingBytes state).length + input.val.length := by omega
      have filledLen : filled.val.length = 16 := by simp
      have assembled : filled.val = pendingBytes state ++ input.val.take copied.val := by
        have all : filled.val.take 16 = filled.val := List.take_of_length_le (by omega)
        simpa only [full, all] using prefixEq
      simp only [full_marker, Aeneas.Std.bind_tc_ok]
      step with block_step_source state.h state.r state.r_times_five filled ready.accumulatorFits ready.keyFits ready.keyCache
        as ⟨afterFirst, liveAfter, firstEq⟩
      step as ⟨rest, restEq, restLen⟩
      have exactRest : rest.val = input.val.drop copied.val := restEq
      refine WP.spec_mono (source_drain_and_save state afterFirst filled rest liveAfter ready) ?_
      intro out updated
      have equation := feed_full (stateMultiplier state) (stateField state) (pendingBytes state) input.val
        pendingFit enough
      unfold UpdateEffect
      rw [equation, ← filling]
      simpa only [firstEq, assembled, exactRest, stateMultiplier, stateField] using updated

/-- The actual Rust one-shot entry point initializes, consumes the complete
input and returns its RFC 8439 tag for every key and input slice. -/
theorem source_authenticate_refines (key : Aeneas.Std.Array U8 32#usize) (input : Slice U8) :
    authenticate key input ⦃ tag => blockValue tag = authenticateInteger key.val input.val ⦄ := by
  unfold authenticate
  step with (source_new_refines key) as ⟨initial, ready, withR, withPad, start, startCount, startPending⟩
  step with (source_update_refines initial input ready) as ⟨state, updateEq⟩
  obtain ⟨stateReady, sameR, _, samePad, feed⟩ := updateEq
  step with (source_finalize_refines state stateReady) as ⟨tag, tagEq⟩
  have initialPending : pendingBytes initial = [] := by simp [pendingBytes, startCount]
  have initialField : stateField initial = 0 := by simp [stateField, start]
  have incoming := feed
  rw [initialPending, List.nil_append, initialField] at incoming
  have fieldEq := congrArg Prod.fst incoming
  have tailEq := congrArg Prod.snd incoming
  change stateField state = _ at fieldEq
  change pendingBytes state = _ at tailEq
  have keyEq : stateMultiplier state = stateMultiplier initial := by simp [stateMultiplier, sameR]
  rw [tagEq, final_residue_eq state stateReady, keyEq, samePad]
  change (commitTail (stateMultiplier initial) (stateField state) (pendingBytes state) + initial.pad.val) % 2^128 = _
  rw [fieldEq, tailEq]
  simp only [authenticateInteger, stateMultiplier, withR, withPad]

#print axioms blocks_append
#print axioms source_copy_pending_refines
#print axioms source_absorb_blocks_refines
#print axioms source_update_refines
#print axioms source_authenticate_refines

end Abc.Refine.Poly1305.Stream
