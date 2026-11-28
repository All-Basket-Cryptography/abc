import Abc.ChaCha20.Extracted.Funs
import ChaCha20QuarterRound

namespace Abc.Refine.ChaCha20

open Aeneas Aeneas.Std
open Abc.Spec.ChaCha20

abbrev StateArray := Aeneas.Std.Array U32 16#usize

def stateView (state : StateArray) : State := fun i => state.val[i.val]!.bv

private theorem index_ok {α : Type} [Inhabited α] {n : Usize}
    (state : Aeneas.Std.Array α n) (i : Usize) (bound : i.val < n.val) :
    state.index_usize i = .ok state[i]! := by
  have within : i.val < state.val.length := by simpa using bound
  simp [Aeneas.Std.Array.index_usize, Aeneas.Std.Array.getElem?_Usize_eq,
    Aeneas.Std.Array.getElem!_Usize_eq, getElem?_pos state.val i.val within]

private theorem update_ok {n : Usize} (state : Aeneas.Std.Array U32 n)
    (i : Usize) (x : U32) (bound : i.val < n.val) :
    state.update i x = .ok (state.set i x) := by
  have within : i.val < state.val.length := by simpa using bound
  simp [Aeneas.Std.Array.update, Aeneas.Std.Array.set,
    Aeneas.Std.Array.getElem?_Usize_eq, getElem?_pos state.val i.val within]

private theorem get_set_same (state : StateArray) (i : Usize) (x : U32)
    (bound : i.val < 16) : (state.set i x)[i]! = x :=
  Aeneas.Std.Array.getElem!_Usize_set_eq _ _ _ _ ⟨rfl, by simpa using bound⟩

private theorem get_set_other (state : StateArray) (i j : Usize) (x : U32)
    (distinct : i.val ≠ j.val) : (state.set i x)[j]! = state[j]! :=
  Aeneas.Std.Array.getElem!_Usize_set_ne _ _ _ _ distinct

private theorem rotation_view (word count : U32) :
    (core.num.U32.rotate_left word count).bv = word.bv.rotateLeft count.val := rfl

private theorem stateView_set (state : StateArray) (i : Usize) (x : U32)
    (bound : i.val < 16) (j : Fin 16) :
    stateView (state.set i x) j = if j.val = i.val then x.bv else stateView state j := by
  by_cases eq : j.val = i.val
  · rw [if_pos eq]
    simp only [stateView, eq]
    have lookup := congrArg UScalar.bv (get_set_same state i x bound)
    simpa only [Aeneas.Std.Array.getElem!_Usize_eq] using lookup
  · rw [if_neg eq]
    have lookup := congrArg UScalar.bv
      (Aeneas.Std.Array.getElem!_Nat_set_ne state i j.val x (Ne.symm eq))
    simpa only [stateView, Aeneas.Std.Array.getElem!_Nat_eq] using lookup

/-- The extracted Rust quarter round succeeds and matches the full state transformation
for every state and every four distinct in-range indices. -/
theorem quarter_round_refines (state : StateArray) (a b c d : Usize)
    (ha : a.val < 16) (hb : b.val < 16) (hc : c.val < 16) (hd : d.val < 16)
    (hab : a.val ≠ b.val) (hac : a.val ≠ c.val) (had : a.val ≠ d.val)
    (hbc : b.val ≠ c.val) (hbd : b.val ≠ d.val) (hcd : c.val ≠ d.val) :
    ∃ out, Abc.ChaCha20.Extracted.quarter_round state (Aeneas.Std.Array.make 4#usize [a, b, c, d]) =
      .ok out ∧ stateView out = quarterRoundAt (stateView state) ⟨a.val, ha⟩ ⟨b.val, hb⟩
        ⟨c.val, hc⟩ ⟨d.val, hd⟩ := by
  have ha' : a.val < 16#usize.val := ha
  have hb' : b.val < 16#usize.val := hb
  have hc' : c.val < 16#usize.val := hc
  have hd' : d.val < 16#usize.val := hd
  have hba := Ne.symm hab
  have hca := Ne.symm hac
  have hda := Ne.symm had
  have hcb := Ne.symm hbc
  have hdb := Ne.symm hbd
  have hdc := Ne.symm hcd
  let indices := Aeneas.Std.Array.make 4#usize [a, b, c, d]
  have readA : indices.index_usize 0#usize = .ok a := rfl
  have readB : indices.index_usize 1#usize = .ok b := rfl
  have readC : indices.index_usize 2#usize = .ok c := rfl
  have readD : indices.index_usize 3#usize = .ok d := rfl
  change ∃ out, Abc.ChaCha20.Extracted.quarter_round state indices = .ok out ∧ _
  simp (disch := first | assumption | decide) only [Abc.ChaCha20.Extracted.quarter_round,
    readA, readB, readC, readD, index_ok, update_ok,
    lift, Aeneas.Std.bind_tc_ok, get_set_same, get_set_other]
  refine ⟨_, rfl, ?_⟩
  funext j
  simp (disch := assumption) only [stateView_set, quarterRoundAt, Fin.ext_iff]
  by_cases ja : j.val = a.val <;> by_cases jb : j.val = b.val <;>
    by_cases jc : j.val = c.val <;> by_cases jd : j.val = d.val <;>
    first | (exfalso; omega) | simp only [ja, jb, jc, jd, hab, hac, had, hbc, hbd, hcd,
      hba, hca, hda, hcb, hdb, hdc, if_true, if_false, quarterRound, stateView, rotation_view,
      core.num.U32.wrapping_add_bv_eq, UScalar.bv_xor, Aeneas.Std.Array.getElem!_Usize_eq] <;> rfl

#print axioms quarter_round_refines

/-- All eight indexed operations refine the specified column and diagonal rounds. -/
theorem double_round_refines (state : StateArray) :
    ∃ out, Abc.ChaCha20.Extracted.double_round state = .ok out ∧
      stateView out = doubleRound (stateView state) := by
  obtain ⟨s1, ok1, view1⟩ := quarter_round_refines state 0#usize 4#usize 8#usize 12#usize
    (by decide) (by decide) (by decide) (by decide)
    (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  obtain ⟨s2, ok2, view2⟩ := quarter_round_refines s1 1#usize 5#usize 9#usize 13#usize
    (by decide) (by decide) (by decide) (by decide)
    (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  obtain ⟨s3, ok3, view3⟩ := quarter_round_refines s2 2#usize 6#usize 10#usize 14#usize
    (by decide) (by decide) (by decide) (by decide)
    (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  obtain ⟨s4, ok4, view4⟩ := quarter_round_refines s3 3#usize 7#usize 11#usize 15#usize
    (by decide) (by decide) (by decide) (by decide)
    (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  obtain ⟨s5, ok5, view5⟩ := quarter_round_refines s4 0#usize 5#usize 10#usize 15#usize
    (by decide) (by decide) (by decide) (by decide)
    (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  obtain ⟨s6, ok6, view6⟩ := quarter_round_refines s5 1#usize 6#usize 11#usize 12#usize
    (by decide) (by decide) (by decide) (by decide)
    (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  obtain ⟨s7, ok7, view7⟩ := quarter_round_refines s6 2#usize 7#usize 8#usize 13#usize
    (by decide) (by decide) (by decide) (by decide)
    (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  obtain ⟨s8, ok8, view8⟩ := quarter_round_refines s7 3#usize 4#usize 9#usize 14#usize
    (by decide) (by decide) (by decide) (by decide)
    (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  refine ⟨s8, ?_, ?_⟩
  · simp only [Abc.ChaCha20.Extracted.double_round, ok1, ok2, ok3, ok4, ok5, ok6, ok7, ok8,
      Aeneas.Std.bind_tc_ok]
  · rw [view8, view7, view6, view5, view4, view3, view2, view1]
    rfl

/-- Ten extracted double rounds produce the twenty-round state for every input. -/
theorem rounds_20_refines (state : StateArray) :
    ∃ out, Abc.ChaCha20.Extracted.rounds_20 state = .ok out ∧
      stateView out = repeatDouble 10 (stateView state) := by
  obtain ⟨s1, ok1, view1⟩ := double_round_refines state
  obtain ⟨s2, ok2, view2⟩ := double_round_refines s1
  obtain ⟨s3, ok3, view3⟩ := double_round_refines s2
  obtain ⟨s4, ok4, view4⟩ := double_round_refines s3
  obtain ⟨s5, ok5, view5⟩ := double_round_refines s4
  obtain ⟨s6, ok6, view6⟩ := double_round_refines s5
  obtain ⟨s7, ok7, view7⟩ := double_round_refines s6
  obtain ⟨s8, ok8, view8⟩ := double_round_refines s7
  obtain ⟨s9, ok9, view9⟩ := double_round_refines s8
  obtain ⟨s10, ok10, view10⟩ := double_round_refines s9
  refine ⟨s10, ?_, ?_⟩
  · simp only [Abc.ChaCha20.Extracted.rounds_20, ok1, ok2, ok3, ok4, ok5, ok6, ok7, ok8,
      ok9, ok10, Aeneas.Std.bind_tc_ok]
  · rw [view10, view9, view8, view7, view6, view5, view4, view3, view2, view1]
    rfl

/-- The extracted Rust block word function, including counter installation and all
sixteen modular additions, refines the RFC word function for every input. -/
theorem block_words_refines (state : StateArray) (counter : U32) :
    ∃ out, Abc.ChaCha20.Extracted.block_words state counter = .ok out ∧
      stateView out = blockWords (stateView state) counter.bv := by
  let initial := state.set 12#usize counter
  have updateCounter : state.update 12#usize counter = .ok initial :=
    update_ok state 12#usize counter (by decide)
  have viewInitial : stateView initial = withCounter (stateView state) counter.bv := by
    funext i
    exact stateView_set state 12#usize counter (by decide) i
  obtain ⟨transformed, okRounds, viewRounds⟩ := rounds_20_refines initial
  simp (disch := decide) only [Abc.ChaCha20.Extracted.block_words, updateCounter, okRounds,
    index_ok, lift, Aeneas.Std.bind_tc_ok]
  refine ⟨_, rfl, ?_⟩
  funext i
  simp only [blockWords, ← viewInitial, ← viewRounds]
  fin_cases i <;> simp only [stateView, Aeneas.Std.Array.getElem!_Usize_eq,
    ← core.num.U32.wrapping_add_bv_eq] <;> rfl

#print axioms double_round_refines
#print axioms rounds_20_refines
#print axioms block_words_refines

def byteView {n : Usize} (bytes : Aeneas.Std.Array U8 n) : Bytes n.val :=
  fun i => bytes.val[i.val]!.bv

private theorem shl_ok (word count : U32) (bound : count.val < 32) :
    (word <<< count) = .ok (⟨word.bv.shiftLeft count.val⟩ : U32) := by
  change (if count.val < 32 then Result.ok (⟨word.bv.shiftLeft count.val⟩ : U32)
    else Result.fail .integerOverflow) = _
  rw [if_pos bound]

private theorem shr_ok (word count : U32) (bound : count.val < 32) :
    (word >>> count) = .ok (⟨word.bv.ushiftRight count.val⟩ : U32) := by
  change (if count.val < 32 then Result.ok (⟨word.bv.ushiftRight count.val⟩ : U32)
    else Result.fail .integerOverflow) = _
  rw [if_pos bound]

private theorem load_word_bits (a b c d : BitVec 8) :
    ((a.setWidth 32 ||| (b.setWidth 32).shiftLeft 8) ||| (c.setWidth 32).shiftLeft 16)
      ||| (d.setWidth 32).shiftLeft 24 = loadLe a b c d := by
  let decoded := ((a.setWidth 32 ||| (b.setWidth 32).shiftLeft 8) ||| (c.setWidth 32).shiftLeft 16)
    ||| (d.setWidth 32).shiftLeft 24
  change decoded = loadLe a b c d
  apply BitVec.eq_of_getLsbD_eq
  suffices h : ∀ i : Fin 32, decoded.getLsbD i.val = (loadLe a b c d).getLsbD i.val by
    exact fun i hi => h ⟨i, hi⟩
  intro i
  simp only [loadLe, BitVec.getLsbD_append]
  fin_cases i <;> simp (disch := decide) [decoded]

theorem load_word_refines (a b c d : U8) :
    Abc.ChaCha20.Extracted.load_word a b c d = .ok ⟨loadLe a.bv b.bv c.bv d.bv⟩ := by
  simp (disch := decide) only [Abc.ChaCha20.Extracted.load_word, shl_ok, lift, Aeneas.Std.bind_tc_ok]
  apply congrArg (Result.ok : U32 → Result U32)
  apply (UScalar.eq_equiv_bv_eq _ _).mpr
  simp only [UScalar.bv_or, UScalar.cast_bv_eq]
  exact load_word_bits a.bv b.bv c.bv d.bv

private theorem add_index (a b result : Usize) (h : a.val + b.val = result.val) :
    (a + b : Result Usize) = .ok result := by
  change UScalar.tryMk .Usize (a.val + b.val) = _
  rw [h]
  have bound : result.val < 2 ^ System.Platform.numBits := result.bv.isLt
  simp [UScalar.tryMk, UScalar.tryMkOpt, bound, Result.ofOption, UScalar.ofNatCore]
  exact UScalar.eq_of_val_eq rfl

set_option maxHeartbeats 800000 in
/-- The extracted initial-state function interprets every valid key/nonce byte
array according to the RFC word layout, including the four constants. -/
theorem initial_state_refines (key : Aeneas.Std.Array U8 32#usize)
    (nonce : Aeneas.Std.Array U8 12#usize) :
    ∃ out, Abc.ChaCha20.Extracted.initial_state key nonce = .ok out ∧
      stateView out = initialFromBytes (byteView key) (byteView nonce) := by
  have add0_1 := add_index 0#usize 1#usize 1#usize (by decide)
  have add0_2 := add_index 0#usize 2#usize 2#usize (by decide)
  have add0_3 := add_index 0#usize 3#usize 3#usize (by decide)
  have add4_1 := add_index 4#usize 1#usize 5#usize (by decide)
  have add4_2 := add_index 4#usize 2#usize 6#usize (by decide)
  have add4_3 := add_index 4#usize 3#usize 7#usize (by decide)
  have add8_1 := add_index 8#usize 1#usize 9#usize (by decide)
  have add8_2 := add_index 8#usize 2#usize 10#usize (by decide)
  have add8_3 := add_index 8#usize 3#usize 11#usize (by decide)
  have add12_1 := add_index 12#usize 1#usize 13#usize (by decide)
  have add12_2 := add_index 12#usize 2#usize 14#usize (by decide)
  have add12_3 := add_index 12#usize 3#usize 15#usize (by decide)
  have add16_1 := add_index 16#usize 1#usize 17#usize (by decide)
  have add16_2 := add_index 16#usize 2#usize 18#usize (by decide)
  have add16_3 := add_index 16#usize 3#usize 19#usize (by decide)
  have add20_1 := add_index 20#usize 1#usize 21#usize (by decide)
  have add20_2 := add_index 20#usize 2#usize 22#usize (by decide)
  have add20_3 := add_index 20#usize 3#usize 23#usize (by decide)
  have add24_1 := add_index 24#usize 1#usize 25#usize (by decide)
  have add24_2 := add_index 24#usize 2#usize 26#usize (by decide)
  have add24_3 := add_index 24#usize 3#usize 27#usize (by decide)
  have add28_1 := add_index 28#usize 1#usize 29#usize (by decide)
  have add28_2 := add_index 28#usize 2#usize 30#usize (by decide)
  have add28_3 := add_index 28#usize 3#usize 31#usize (by decide)
  simp (disch := decide) only [Abc.ChaCha20.Extracted.initial_state, index_ok, load_word_refines,
    add0_1, add0_2, add0_3, add4_1, add4_2, add4_3,
    add8_1, add8_2, add8_3, add12_1, add12_2, add12_3,
    add16_1, add16_2, add16_3, add20_1, add20_2, add20_3,
    add24_1, add24_2, add24_3, add28_1, add28_2, add28_3,
    Aeneas.Std.bind_tc_ok]
  refine ⟨_, rfl, ?_⟩
  funext i
  fin_cases i <;> simp only [stateView, initialFromBytes, byteView,
    Aeneas.Std.Array.getElem!_Usize_eq] <;> rfl

private theorem cast_shift_byte (word : U32) (count : Nat) :
    (UScalar.cast .U8 (⟨word.bv.ushiftRight count⟩ : U32)).bv =
      word.bv.extractLsb' count 8 := by
  simp only [UScalar.cast_bv_eq, BitVec.extractLsb', BitVec.setWidth]
  rfl

set_option maxHeartbeats 1800000 in
set_option maxRecDepth 4096 in
/-- Each of the 64 extracted bytes matches the corresponding little-endian
coordinate of all sixteen input words. -/
theorem serialize_refines (words : StateArray) :
    ∃ out, Abc.ChaCha20.Extracted.serialize words = .ok out ∧
      byteView out = serializeBytes (stateView words) := by
  simp (disch := decide) only [Abc.ChaCha20.Extracted.serialize, index_ok, shr_ok,
    lift, Aeneas.Std.bind_tc_ok]
  refine ⟨_, rfl, ?_⟩
  funext i
  fin_cases i <;>
    simp only [byteView, serializeBytes, stateView, Aeneas.Std.Array.getElem!_Usize_eq,
      ← cast_shift_byte] <;> rfl

theorem block_refines (initial : StateArray) (counter : U32) :
    ∃ out, Abc.ChaCha20.Extracted.block initial counter = .ok out ∧
      byteView out = serializeBytes (blockWords (stateView initial) counter.bv) := by
  obtain ⟨words, hwords, wordView⟩ := block_words_refines initial counter
  obtain ⟨out, hout, outView⟩ := serialize_refines words
  refine ⟨out, ?_, ?_⟩
  · simp only [Abc.ChaCha20.Extracted.block, hwords, Aeneas.Std.bind_tc_ok, hout]
  · rw [outView, wordView]

/-- Exact byte-to-byte refinement of the two extracted functions that implement
the RFC block transform along the active Rust keystream path. -/
theorem block_from_bytes_refines (key : Aeneas.Std.Array U8 32#usize)
    (nonce : Aeneas.Std.Array U8 12#usize) (counter : U32) :
    ∃ initial out, Abc.ChaCha20.Extracted.initial_state key nonce = .ok initial ∧
      Abc.ChaCha20.Extracted.block initial counter = .ok out ∧
      byteView out = blockBytes (byteView key) (byteView nonce) counter.bv := by
  obtain ⟨initial, hinit, iniView⟩ := initial_state_refines key nonce
  obtain ⟨out, hout, outView⟩ := block_refines initial counter
  refine ⟨initial, out, hinit, hout, ?_⟩
  simpa only [blockBytes, iniView] using outView

#print axioms load_word_refines
#print axioms initial_state_refines
#print axioms serialize_refines
#print axioms block_refines
#print axioms block_from_bytes_refines

end Abc.Refine.ChaCha20
