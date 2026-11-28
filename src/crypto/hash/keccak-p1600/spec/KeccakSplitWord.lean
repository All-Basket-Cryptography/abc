import Init.Data.BitVec.Lemmas

namespace Abc.Spec.KeccakSplitWord

def rotateHalf (low high : BitVec 32) (count : Nat) : BitVec 32 :=
  if count < 32 then
    if count = 0 then low
    else (low <<< count) ||| (high >>> (32 - count))
  else
    if count = 32 then high
    else (high <<< (count - 32)) ||| (low >>> (64 - count))

theorem rotate_lanes (low high : BitVec 32) (count : Nat) (bound : count < 64) :
    (rotateHalf high low count).append (rotateHalf low high count) =
      (high.append low).rotateLeft count := by
  apply BitVec.eq_of_getLsbD_eq
  intro index within
  by_cases small : count < 32
  · by_cases zero : count = 0
    · subst count
      simp [rotateHalf]
      omega
    · simp [rotateHalf, small, zero]
      grind
  · by_cases half : count = 32
    · subst count
      simp [rotateHalf]
      grind
    · simp [rotateHalf, small, half]
      grind

#print axioms rotate_lanes

end Abc.Spec.KeccakSplitWord
