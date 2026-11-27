import Abc.Sha256.Extracted.Funs
import CompressionRefinement
import WordRefinement

set_option maxHeartbeats 1000000
set_option maxRecDepth 2048

namespace Abc.Refine.Sha256.Implementation

open Aeneas Aeneas.Std Result ControlFlow

open Abc.Refinement.Sha256 (growSpecSchedule seedSpecSchedule)

private theorem fromLEBytes_toNat (bytes : List Abc.Spec.Sha256.Byte) :
    (BitVec.fromLEBytes bytes).toNat = Abc.Foundation.decodeBigEndian bytes.reverse := by
  induction bytes with
  | nil => rfl
  | cons byte tail ih =>
    rw [List.reverse_cons, Abc.Refinement.Sha256.decodeBigEndian_append_byte, ← ih]
    exact Abc.Refinement.Sha256.lowByte_toNat (BitVec.fromLEBytes tail) byte

private theorem fromBEBytes_toNat (bytes : List Abc.Spec.Sha256.Byte) :
    (BitVec.fromBEBytes bytes).toNat = Abc.Foundation.decodeBigEndian bytes := by
  simp only [BitVec.fromBEBytes, BitVec.toNat_cast, fromLEBytes_toNat, List.reverse_reverse]

/-- The Aeneas model of `u32::from_be_bytes` agrees with the independent spec. -/
theorem from_be_bytes_refines (bytes : Aeneas.Std.Array U8 4#usize) :
    (core.num.U32.from_be_bytes bytes).bv = Abc.Spec.Sha256.parseWord (bytesView bytes.val) := by
  have length : (bytesView bytes.val).length = 4 := by simp
  have width : 8 * (bytesView bytes.val).length = 32 := by omega
  have bound : Abc.Foundation.decodeBigEndian (bytesView bytes.val) < 2 ^ 32 := by
    have fits := (BitVec.fromBEBytes (bytesView bytes.val)).isLt
    simpa only [fromBEBytes_toNat, width] using fits
  apply BitVec.eq_of_toNat_eq
  change ((BitVec.fromBEBytes (bytesView bytes.val)).cast width).toNat = _
  rw [BitVec.toNat_cast, fromBEBytes_toNat, Abc.Spec.Sha256.parseWord, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt bound]

private theorem from_be_bytes_spec (bytes : Aeneas.Std.Array U8 4#usize) :
    lift (core.num.U32.from_be_bytes bytes) ⦃ word => word.bv = Abc.Spec.Sha256.parseWord (bytesView bytes.val) ⦄ := by
  simpa [lift, WP.spec_ok] using from_be_bytes_refines bytes

private def wordAt {n : Usize} (words : Aeneas.Std.Array U32 n) (i : Nat) : Abc.Spec.Sha256.Word :=
  (words.val[i]?.getD 0#u32).bv

private theorem wordAt_set_self {n : Usize} (words : Aeneas.Std.Array U32 n) (i : Usize)
    (word : U32) (bound : i.val < words.val.length) : wordAt (words.set i word) i.val = word.bv := by
  simp [wordAt, List.getElem?_set_self bound]

private theorem wordAt_set_ne {n : Usize} (words : Aeneas.Std.Array U32 n) (i : Usize)
    (word : U32) (j : Nat) (different : i.val ≠ j) : wordAt (words.set i word) j = wordAt words j := by
  simp [wordAt, List.getElem?_set_ne different]

private theorem wordAt_index {n : Usize} (words : Aeneas.Std.Array U32 n) (i : Usize)
    (bound : i.val < words.val.length) : words.index_usize i ⦃ word => word.bv = wordAt words i.val ⦄ := by
  have lookup := Array.index_usize_spec words i (by simpa using bound)
  apply WP.spec_mono lookup
  intro word eq
  simp [wordAt, eq, getElem?_pos words.val i.val bound]

private def parseAt (block : Slice U8) (i : Nat) : Abc.Spec.Sha256.Word :=
  Abc.Spec.Sha256.parseWord (((bytesView block.val).drop (4 * i)).take 4)

private def loadInv (block : Slice U8) (entry : Aeneas.Std.Array U32 64#usize × Usize) : Prop :=
  entry.2.val ≤ 16 ∧ ∀ i < entry.2.val, wordAt entry.1 i = parseAt block i

private theorem parseAt_bytes (block : Slice U8) (i : Nat) (bound : 4 * i + 4 ≤ block.val.length) :
    Abc.Spec.Sha256.parseWord (bytesView [block.val[4 * i]'(by omega), block.val[4 * i + 1]'(by omega),
      block.val[4 * i + 2]'(by omega), block.val[4 * i + 3]'(by omega)]) = parseAt block i := by
  unfold parseAt
  rw [← bytesView_drop, ← bytesView_take]
  rw [Abc.Refinement.Sha256.takeFour_eq_elements block.val (4 * i) bound]

/-- Parsing the exact generated loop terminates and records sixteen big-endian words. -/
theorem compress_load_refines (block : Slice U8) (hBlock : block.val.length = 64)
    (start : Aeneas.Std.Array U32 64#usize) :
    Abc.Sha256.Extracted.compress_loop0 block start 0#usize ⦃ data =>
      data.2.val = 16 ∧ ∀ i < 16, wordAt data.1 i = parseAt block i ⦄ := by
  unfold Abc.Sha256.Extracted.compress_loop0
  refine Aeneas.Std.loop.spec_decr_nat (fun entry => 16 - entry.2.val) (loadInv block) _ _ _ ?_ ?_
  · rintro ⟨words, i⟩ ⟨bound, loaded⟩
    dsimp only at bound loaded ⊢
    unfold Abc.Sha256.Extracted.compress_loop0.body
    split
    · rename_i condition
      have inRange : i.val < 16 := by scalar_tac
      step as ⟨offset, offsetEq⟩
      step as ⟨b0, byte0Eq⟩
      step as ⟨offset1, offset1Eq⟩
      step as ⟨b1, byte1Eq⟩
      step as ⟨offset2, offset2Eq⟩
      step as ⟨b2, byte2Eq⟩
      step as ⟨offset3, offset3Eq⟩
      step as ⟨b3, byte3Eq⟩
      step with from_be_bytes_spec as ⟨word, wordEq⟩
      step as ⟨updated, updatedEq⟩
      step as ⟨next, nextEq⟩
      refine ⟨⟨by scalar_tac, ?_⟩, by scalar_tac⟩
      intro j beforeNext
      have oldLen : i.val < words.val.length := by simp; omega
      rw [updatedEq]
      by_cases equal : j = i.val
      · subst j
        rw [wordAt_set_self _ _ _ oldLen, wordEq, Aeneas.Std.Array.make_val]
        have h0 : offset.val = 4 * i.val := by scalar_tac
        have h1 : offset1.val = 4 * i.val + 1 := by scalar_tac
        have h2 : offset2.val = 4 * i.val + 2 := by scalar_tac
        have h3 : offset3.val = 4 * i.val + 3 := by scalar_tac
        rw [byte0Eq, byte1Eq, byte2Eq, byte3Eq]
        simp only [h0, h1, h2, h3]
        exact parseAt_bytes block i.val (by omega)
      · rw [wordAt_set_ne _ _ _ _ (Ne.symm equal)]
        exact loaded j (by scalar_tac)
    · rename_i condition
      have indexDone : i.val = 16 := by scalar_tac
      simpa [WP.spec_ok, indexDone] using And.intro indexDone loaded
  · simp [loadInv]

private def specSchedulePrefix (block : Abc.Spec.Sha256.Message) (count : Nat) : _root_.Array Abc.Spec.Sha256.Word :=
  (List.range count).foldl growSpecSchedule (seedSpecSchedule block)

@[simp] private theorem specSchedulePrefix_size (block : Abc.Spec.Sha256.Message) (count : Nat) :
    (specSchedulePrefix block count).size = count + 16 := by
  induction count with
  | zero => simp [specSchedulePrefix, seedSpecSchedule]
  | succ count ih =>
    unfold specSchedulePrefix at ih ⊢
    simp only [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil,
      growSpecSchedule, _root_.Array.size_push, ih]

private theorem seedSpecSchedule_getD (block : Abc.Spec.Sha256.Message) (i : Nat) (bound : i < 16) :
    (seedSpecSchedule block).getD i 0 = Abc.Spec.Sha256.parseWord ((block.drop (4 * i)).take 4) := by
  simp [seedSpecSchedule, bound]

private def expandInv (block : Abc.Spec.Sha256.Message) (entry : Aeneas.Std.Array U32 64#usize × Usize) : Prop :=
  16 ≤ entry.2.val ∧ entry.2.val ≤ 64 ∧
    ∀ i < entry.2.val, wordAt entry.1 i = (specSchedulePrefix block (entry.2.val - 16)).getD i 0

private theorem schedule_word_spec (w16 w15 w7 w2 : U32) :
    Abc.Sha256.Extracted.schedule_word w16 w15 w7 w2 ⦃ word =>
      word.bv = Abc.Spec.Sha256.scheduleOne w2.bv + w7.bv + Abc.Spec.Sha256.scheduleZero w15.bv + w16.bv ⦄ := by
  rw [WP.spec_equiv_exists]
  exact schedule_word_refines w16 w15 w7 w2

/-- The generated recurrence extends the parsed schedule through round 63. -/
theorem compress_expand_refines (block : Slice U8) (words : Aeneas.Std.Array U32 64#usize)
    (start : Usize) (indexStart : start.val = 16)
    (loaded : ∀ i < 16, wordAt words i = parseAt block i) :
    Abc.Sha256.Extracted.compress_loop1 words start ⦃ expanded =>
      ∀ i < 64, wordAt expanded i = (Abc.Spec.Sha256.messageSchedule (bytesView block.val)).getD i 0 ⦄ := by
  unfold Abc.Sha256.Extracted.compress_loop1
  refine Aeneas.Std.loop.spec_decr_nat (fun entry => 64 - entry.2.val) (expandInv (bytesView block.val))
    _ _ _ ?_ ?_
  · rintro ⟨current, i⟩ ⟨lower, upper, agrees⟩
    dsimp only at lower upper agrees ⊢
    unfold Abc.Sha256.Extracted.compress_loop1.body
    split
    · rename_i condition
      have inRange : i.val < 64 := by scalar_tac
      step as ⟨offset16, offset16Eq⟩
      step with wordAt_index as ⟨w16, w16Eq⟩
      step as ⟨offset15, offset15Eq⟩
      step with wordAt_index as ⟨w15, w15Eq⟩
      step as ⟨offset7, offset7Eq⟩
      step with wordAt_index as ⟨w7, w7Eq⟩
      step as ⟨offset2, offset2Eq⟩
      step with wordAt_index as ⟨w2, w2Eq⟩
      step with schedule_word_spec as ⟨computed, computedEq⟩
      step as ⟨updated, updatedEq⟩
      step as ⟨next, nextEq⟩
      refine ⟨⟨by scalar_tac, by scalar_tac, ?_⟩, by scalar_tac⟩
      intro j beforeNext
      let growing := specSchedulePrefix (bytesView block.val) (i.val - 16)
      have growingSize : growing.size = i.val := by simp [growing]; omega
      have advanced : next.val - 16 = (i.val - 16).succ := by scalar_tac
      rw [updatedEq, advanced]
      simp only [specSchedulePrefix, List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
      change wordAt (current.set i computed) j = (growSpecSchedule growing (i.val - 16)).getD j 0
      unfold growSpecSchedule
      rw [_root_.Array.getD_eq_getD_getElem?, _root_.Array.getElem?_push, growingSize]
      by_cases written : j = i.val
      · subst j
        rw [wordAt_set_self _ _ _ (by scalar_tac), if_pos rfl, Option.getD_some, computedEq]
        have h16 : offset16.val = i.val - 16 := by scalar_tac
        have h15 : offset15.val = i.val - 16 + 1 := by scalar_tac
        have h7 : offset7.val = i.val - 16 + 9 := by scalar_tac
        have h2 : offset2.val = i.val - 16 + 14 := by scalar_tac
        rw [w16Eq, w15Eq, w7Eq, w2Eq, h16, h15, h7, h2,
          agrees _ (by omega), agrees _ (by omega), agrees _ (by omega), agrees _ (by omega)]
      · rw [wordAt_set_ne _ _ _ _ (Ne.symm written), if_neg written]
        simpa only [_root_.Array.getD_eq_getD_getElem?] using agrees j (by scalar_tac)
    · rename_i condition
      have indexDone : i.val = 64 := by scalar_tac
      simp only [WP.spec_ok]
      rw [indexDone] at agrees
      exact agrees
  · unfold expandInv
    dsimp only
    rw [indexStart]
    refine ⟨by decide, by decide, ?_⟩
    intro j bound
    change wordAt words j = (seedSpecSchedule (bytesView block.val)).getD j 0
    rw [seedSpecSchedule_getD _ _ bound]
    exact loaded j bound

private theorem constantWordAt (i : Nat) :
    wordAt Abc.Sha256.Extracted.ROUND_CONSTANTS i = Abc.Spec.Sha256.constants.getD i 0 := by
  rw [_root_.Array.getD_eq_getD_getElem?, ← _root_.Array.getElem?_toList, ← round_constants_refine]
  simp only [wordAt, List.getElem?_map]
  cases Abc.Sha256.Extracted.ROUND_CONSTANTS.val[i]? <;> rfl

private theorem round_step_spec (state : Aeneas.Std.Array U32 8#usize) (constant word : U32) :
    Abc.Sha256.Extracted.round_step state constant word ⦃ work =>
      stateView work = Abc.Spec.Sha256.round (stateView state) constant.bv word.bv ⦄ := by
  rw [WP.spec_equiv_exists]
  exact round_step_refines state constant word

private def roundPrefix (schedule : _root_.Array Abc.Spec.Sha256.Word) (initial : Abc.Spec.Sha256.State) (count : Nat) : Abc.Spec.Sha256.State :=
  (List.range count).foldl
    (fun work i => Abc.Spec.Sha256.round work (Abc.Spec.Sha256.constants.getD i 0) (schedule.getD i 0)) initial

private def roundInv (schedule : _root_.Array Abc.Spec.Sha256.Word) (initial : Abc.Spec.Sha256.State)
    (entry : Aeneas.Std.Array U32 8#usize × Usize) : Prop :=
  entry.2.val ≤ 64 ∧ stateView entry.1 = roundPrefix schedule initial entry.2.val

/-- The generated round loop visits every specification round in order. -/
theorem compress_rounds_refine (schedule : _root_.Array Abc.Spec.Sha256.Word)
    (words : Aeneas.Std.Array U32 64#usize) (initial : Aeneas.Std.Array U32 8#usize)
    (agrees : ∀ i < 64, wordAt words i = schedule.getD i 0) :
    Abc.Sha256.Extracted.compress_loop2 words initial 0#usize ⦃ work =>
      stateView work = roundPrefix schedule (stateView initial) 64 ⦄ := by
  unfold Abc.Sha256.Extracted.compress_loop2
  refine Aeneas.Std.loop.spec_decr_nat (fun entry => 64 - entry.2.val) (roundInv schedule (stateView initial))
    _ _ _ ?_ ?_
  · rintro ⟨work, i⟩ ⟨upper, prior⟩
    dsimp only at upper prior ⊢
    unfold Abc.Sha256.Extracted.compress_loop2.body
    split
    · rename_i condition
      have inRange : i.val < 64 := by scalar_tac
      step with wordAt_index as ⟨constant, constantEq⟩
      step with wordAt_index as ⟨word, wordEq⟩
      step with round_step_spec as ⟨nextWork, workEq⟩
      step as ⟨nextIndex, nextIndexEq⟩
      refine ⟨⟨by scalar_tac, ?_⟩, by scalar_tac⟩
      have advanced : nextIndex.val = i.val.succ := by scalar_tac
      rw [workEq, prior, constantEq, constantWordAt, wordEq, agrees _ inRange, advanced]
      simp only [roundPrefix, List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
    · rename_i condition
      have indexDone : i.val = 64 := by scalar_tac
      simpa only [WP.spec_ok, indexDone] using prior
  · simp [roundInv, roundPrefix]

/-- The exact Aeneas extraction of the portable Rust compression function
    returns the independent specification's state for every full block. -/
theorem compress_refines (state : Aeneas.Std.Array U32 8#usize) (block : Slice U8)
    (length : block.val.length = 64) :
    ∃ out, Abc.Sha256.Extracted.compress state block = .ok out ∧
      stateView out = Abc.Spec.Sha256.compress (stateView state) (bytesView block.val) := by
  unfold Abc.Sha256.Extracted.compress
  dsimp only
  obtain ⟨loaded, loadEq, indexStart, parsed⟩ :=
    (WP.spec_equiv_exists _ _).mp (compress_load_refines block length (Aeneas.Std.Array.repeat 64#usize 0#u32))
  rw [loadEq]
  rcases loaded with ⟨words, i⟩
  simp only [Aeneas.Std.bind_tc_ok]
  change ∃ out, (do
    let expanded ← Abc.Sha256.Extracted.compress_loop1 words i
    let work ← Abc.Sha256.Extracted.compress_loop2 expanded state 0#usize
    Abc.Sha256.Extracted.feed_forward state work) = .ok out ∧ _
  obtain ⟨expanded, expandEq, scheduleAgrees⟩ :=
    (WP.spec_equiv_exists _ _).mp (compress_expand_refines block words i indexStart parsed)
  simp only [expandEq, Aeneas.Std.bind_tc_ok]
  obtain ⟨work, roundsEq, workView⟩ := (WP.spec_equiv_exists _ _).mp
    (compress_rounds_refine (Abc.Spec.Sha256.messageSchedule (bytesView block.val)) expanded state scheduleAgrees)
  simp only [roundsEq, Aeneas.Std.bind_tc_ok]
  obtain ⟨out, outputEq, outputView⟩ := feed_forward_refines state work
  refine ⟨out, outputEq, ?_⟩
  rw [outputView, workView]
  rfl

end Abc.Refine.Sha256.Implementation
