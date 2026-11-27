import Abc.Sha256.Extracted.Types
import StreamingRefinement

namespace Abc.Refine.Sha256.Implementation

open Aeneas.Std
open Abc.Spec.Sha256

/-- Project the Rust word array in SHA-256 register order. The array size
    ensures each of the eight indices lies in its bounds. -/
def stateView (state : Aeneas.Std.Array U32 8#usize) : State :=
  ⟨(state.val[0]?.getD 0#u32).bv, (state.val[1]?.getD 0#u32).bv,
   (state.val[2]?.getD 0#u32).bv, (state.val[3]?.getD 0#u32).bv,
   (state.val[4]?.getD 0#u32).bv, (state.val[5]?.getD 0#u32).bv,
   (state.val[6]?.getD 0#u32).bv, (state.val[7]?.getD 0#u32).bv⟩

/-- The exact bits of a Rust byte list, in their original order. -/
def bytesView (bytes : List U8) : Message := bytes.map U8.bv

@[simp] theorem bytesView_length (bytes : List U8) : (bytesView bytes).length = bytes.length :=
  List.length_map U8.bv

@[simp] theorem bytesView_append (left right : List U8) :
    bytesView (left ++ right) = bytesView left ++ bytesView right :=
  List.map_append

@[simp] theorem bytesView_take (bytes : List U8) (n : Nat) :
    bytesView (bytes.take n) = (bytesView bytes).take n := by
  simp only [bytesView, List.map_take]

@[simp] theorem bytesView_drop (bytes : List U8) (n : Nat) :
    bytesView (bytes.drop n) = (bytesView bytes).drop n := by
  simp only [bytesView, List.map_drop]

/-- Project the chaining state, live buffer prefix, and byte counter. -/
def streamView (state : Abc.Sha256.Extracted.Sha256) : Streaming.BufferView State :=
  ⟨stateView state.state, bytesView (state.block.val.take state.buffered.val), state.length.val⟩

end Abc.Refine.Sha256.Implementation
