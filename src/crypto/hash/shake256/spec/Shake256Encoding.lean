import Abc.Foundation.Encoding

namespace Abc.Spec.Shake256

abbrev Byte := Abc.Foundation.Byte
def rate : Nat := 136

-- Byte-aligned SHAKE suffix followed by pad10*1.
def paddedTail (tail : List Byte) : List Byte :=
  if tail.length + 1 = rate then tail ++ [0x9f]
  else tail ++ [0x1f] ++ List.replicate (rate - tail.length - 2) 0 ++ [0x80]

theorem padding_fills_rate (tail : List Byte) (within : tail.length < rate) :
    (paddedTail tail).length = rate := by
  unfold paddedTail
  split
  · simp [*]
  · simp only [List.length_append, List.length_cons, List.length_nil, List.length_replicate]
    omega

theorem boundary_suffix (tail : List Byte) (boundary : tail.length + 1 = rate) :
    paddedTail tail = tail ++ [0x9f] := by
  simp [paddedTail, boundary]

/-- Splitting a read leaves the same bytes as one read of the combined length. -/
theorem split_read (stream : List α) (first second : Nat) :
    stream.take first ++ (stream.drop first).take second = stream.take (first + second) := by
  induction first generalizing stream with
  | zero => simp
  | succ n ih =>
    cases stream with
    | nil => simp
    | cons head tail => simp [Nat.succ_add, ih]

#print axioms padding_fills_rate
#print axioms boundary_suffix
#print axioms split_read

end Abc.Spec.Shake256
