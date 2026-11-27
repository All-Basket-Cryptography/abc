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

end Abc.Refine.ChaCha20
