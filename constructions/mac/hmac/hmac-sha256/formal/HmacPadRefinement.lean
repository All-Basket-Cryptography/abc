import Abc.HmacSha256.Extracted.Funs
import HmacSpec
import ModelView

namespace Abc.Refine.HmacSha256.Implementation

open Aeneas Aeneas.Std Result ControlFlow
open Abc.HmacSha256.Extracted (xor_pads xor_pads_loop)
open Abc.Refine.Sha256.Implementation (bytesView)
open Abc.Spec.HmacSha256 (innerPad outerPad zeroPad)

private def padPrefix (material : Slice U8) (constant : U8)
    (output : Aeneas.Std.Array U8 64#usize) (written : Nat) : Prop :=
  ∀ j < 64, output.val[j]? = some
    (if j < written then (material.val[j]?.getD 0#u8) ^^^ constant else constant)

private theorem padPrefix_start (material : Slice U8) (constant : U8) :
    padPrefix material constant (Aeneas.Std.Array.repeat 64#usize constant) 0 := by
  intro j inside
  rw [Aeneas.Std.Array.repeat_val]
  change (List.replicate 64 constant)[j]? = _
  simp only [Nat.not_lt_zero, if_false, List.getElem?_replicate, if_pos inside]

private theorem padPrefix_step (material : Slice U8) (constant : U8)
    (output : Aeneas.Std.Array U8 64#usize) (i : Usize) (byte : U8)
    (within : i.val < material.val.length) (bounded : i.val < 64)
    (read : byte = material.val[i.val]) (prior : padPrefix material constant output i.val) :
    padPrefix material constant (output.set i (byte ^^^ constant)) (i.val + 1) := by
  have inOutput : i.val < output.val.length := by simpa using bounded
  intro j inside
  by_cases current : j = i.val
  · subst j
    rw [Aeneas.Std.Array.set_val_eq, List.getElem?_set_self inOutput, getElem?_pos material.val i.val within]
    simp [read]
  · rw [Aeneas.Std.Array.set_val_eq, List.getElem?_set_ne (Ne.symm current), prior j inside]
    have same : j < i.val + 1 ↔ j < i.val := by omega
    simp only [same]

private theorem padPrefix_complete (material : Slice U8) (constant : U8)
    (bounded : material.val.length ≤ 64) (output : Aeneas.Std.Array U8 64#usize)
    (prior : padPrefix material constant output material.val.length) :
    bytesView output.val = (zeroPad (bytesView material.val)).map (fun byte => byte ^^^ constant.bv) := by
  have viewLength : (bytesView material.val).length = material.val.length := by simp
  have padLength : (zeroPad (bytesView material.val)).length = 64 := by
    simp [zeroPad, viewLength]
    omega
  apply List.ext_getElem?
  intro j
  by_cases inside : j < 64
  · simp only [zeroPad, bytesView, List.getElem?_map, List.getElem?_append, List.length_map]
    rw [prior j inside]
    by_cases written : j < material.val.length
    · rw [if_pos written, if_pos written, getElem?_pos material.val j written]
      simp [UScalar.bv_xor]
    · have inPad : j - material.val.length < 64 - material.val.length := by omega
      simp [if_neg written, inPad]
  · have outputEnd : output.val.length ≤ j := by simpa using Nat.le_of_not_gt inside
    have padEnd : (zeroPad (bytesView material.val)).length ≤ j := by
      simpa only [padLength] using Nat.le_of_not_gt inside
    change (output.val.map U8.bv)[j]? = _
    simp only [List.getElem?_map, List.getElem?_eq_none outputEnd,
      List.getElem?_eq_none padEnd, Option.map_none]

private def padInvariant (material : Slice U8)
    (entry : Aeneas.Std.Array U8 64#usize × Aeneas.Std.Array U8 64#usize × Usize) : Prop :=
  entry.2.2.val ≤ material.val.length ∧
  padPrefix material 54#u8 entry.1 entry.2.2.val ∧
  padPrefix material 92#u8 entry.2.1 entry.2.2.val

/-- The Rust loop writes each key byte and retains the corresponding mask on zero padding. -/
theorem xor_pads_refines (material : Slice U8) (bounded : material.val.length ≤ 64) :
    xor_pads material ⦃ pads =>
      bytesView pads.1.val = innerPad (zeroPad (bytesView material.val)) ∧
      bytesView pads.2.val = outerPad (zeroPad (bytesView material.val)) ⦄ := by
  unfold xor_pads xor_pads_loop
  dsimp only
  refine Aeneas.Std.loop.spec_decr_nat (fun entry => material.val.length - entry.2.2.val)
    (padInvariant material) _ _ _ ?_ ?_
  · rintro ⟨inner, outer, i⟩ ⟨limit, innerPrefix, outerPrefix⟩
    dsimp only at limit innerPrefix outerPrefix ⊢
    unfold Abc.HmacSha256.Extracted.xor_pads_loop.body
    dsimp only
    split
    · rename_i condition
      have within : i.val < material.val.length := by scalar_tac
      have inside : i.val < 64 := by omega
      step as ⟨byte, read⟩
      simp only [lift, bind_tc_ok]
      step as ⟨newInner, innerEq⟩
      step as ⟨newOuter, outerEq⟩
      step as ⟨next, nextEq⟩
      have advanced : next.val = i.val + 1 := by scalar_tac
      refine ⟨⟨by scalar_tac, ?_, ?_⟩, by scalar_tac⟩
      · simpa only [innerEq, advanced] using padPrefix_step material 54#u8 inner i byte within inside read innerPrefix
      · simpa only [outerEq, advanced] using padPrefix_step material 92#u8 outer i byte within inside read outerPrefix
    · rename_i condition
      have done : i.val = material.val.length := by scalar_tac
      simp only [WP.spec_ok]
      exact ⟨padPrefix_complete material 54#u8 bounded inner (done ▸ innerPrefix),
        padPrefix_complete material 92#u8 bounded outer (done ▸ outerPrefix)⟩
  · exact ⟨Nat.zero_le _, padPrefix_start material _, padPrefix_start material _⟩

end Abc.Refine.HmacSha256.Implementation
