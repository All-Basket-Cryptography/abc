import Abc.Sha256.Extracted.Funs
import ModelView

namespace Abc.Refine.Sha256.Implementation

open Aeneas Aeneas.Std
open Abc.Spec.Sha256

private theorem index_state (state : Aeneas.Std.Array U32 8#usize) (i : Usize)
    (bound : i.val < 8) :
    state.index_usize i = .ok (state.val[i.val]?.getD 0#u32) := by
  have valid : i.val < state.val.length := by simpa using bound
  rw [Aeneas.Std.Array.index_usize, Aeneas.Std.Array.getElem?_Usize_eq,
    getElem?_pos state.val i.val valid]
  rfl

private theorem rotate_right_view (x count : U32) :
    (core.num.U32.rotate_right x count).bv = x.bv.rotateRight count.val := rfl

private theorem shift_right_three (x : U32) :
    (x >>> 3#i32) = .ok (⟨x.bv >>> 3⟩ : U32) := rfl

private theorem shift_right_ten (x : U32) :
    (x >>> 10#i32) = .ok (⟨x.bv >>> 10⟩ : U32) := rfl

/-- The extracted word recurrence uses the same four words and modular sum. -/
theorem schedule_word_refines (w16 w15 w7 w2 : U32) :
    ∃ out, Abc.Sha256.Extracted.schedule_word w16 w15 w7 w2 = .ok out ∧
      out.bv = scheduleOne w2.bv + w7.bv + scheduleZero w15.bv + w16.bv := by
  simp only [Abc.Sha256.Extracted.schedule_word, lift, shift_right_three, shift_right_ten,
    Aeneas.Std.bind_tc_ok]
  refine ⟨_, rfl, ?_⟩
  simp only [scheduleOne, scheduleZero, core.num.U32.wrapping_add_bv_eq,
    rotate_right_view, UScalar.bv_xor]
  ac_rfl

/-- A successful extracted round yields the mathematical round for every state. -/
theorem round_step_refines (state : Aeneas.Std.Array U32 8#usize) (constant word : U32) :
    ∃ out, Abc.Sha256.Extracted.round_step state constant word = .ok out ∧
      stateView out = round (stateView state) constant.bv word.bv := by
  simp (disch := decide) only [Abc.Sha256.Extracted.round_step, index_state,
    lift, Aeneas.Std.bind_tc_ok]
  refine ⟨_, rfl, ?_⟩
  simp [stateView, round, sumOne, sumZero, pick, majority, rotate_right_view]

/-- The extracted feed-forward is the componentwise modular state addition. -/
theorem feed_forward_refines (initial work : Aeneas.Std.Array U32 8#usize) :
    ∃ out, Abc.Sha256.Extracted.feed_forward initial work = .ok out ∧
      stateView out = addState (stateView initial) (stateView work) := by
  simp (disch := decide) only [Abc.Sha256.Extracted.feed_forward, index_state,
    lift, Aeneas.Std.bind_tc_ok]
  refine ⟨_, rfl, ?_⟩
  simp [stateView, addState]

theorem round_constants_refine :
    Abc.Sha256.Extracted.ROUND_CONSTANTS.val.map U32.bv = constants.toList := by
  rw [Abc.Sha256.Extracted.ROUND_CONSTANTS, Aeneas.Std.Array.make_val]
  rfl

end Abc.Refine.Sha256.Implementation
