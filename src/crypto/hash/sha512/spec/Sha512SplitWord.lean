import Init.Data.BitVec.Lemmas

namespace Abc.Spec.Sha512SplitWord

def rotateHalf (high low : BitVec 32) (distance : Nat) : BitVec 32 :=
  if distance < 32 then
    (high >>> distance) ||| (low <<< (32 - distance))
  else
    (low >>> (distance - 32)) ||| (high <<< (64 - distance))

theorem rotations (high low : BitVec 32) (distance : Nat)
    (used : distance = 1 ∨ distance = 8 ∨ distance = 19 ∨ distance = 61 ∨
      distance = 14 ∨ distance = 18 ∨ distance = 41 ∨ distance = 28 ∨
      distance = 34 ∨ distance = 39) :
    (rotateHalf high low distance).append (rotateHalf low high distance) =
      (high.append low).rotateRight distance := by
  apply BitVec.eq_of_getLsbD_eq
  intro index within
  rcases used with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp [rotateHalf] <;> grind

theorem shifts (high low : BitVec 32) (distance : Nat) (used : distance = 6 ∨ distance = 7) :
    (high >>> distance).append ((low >>> distance) ||| (high <<< (32 - distance))) =
      (high.append low) >>> distance := by
  apply BitVec.eq_of_getLsbD_eq
  intro index within
  rcases used with rfl | rfl <;> simp <;> grind

def radix : Nat := 2^32

theorem limb_carry (highSum lowSum : Nat) :
    (highSum * radix + lowSum) % (radix * radix) =
      ((highSum + lowSum / radix) % radix) * radix + lowSum % radix := by
  unfold radix
  omega

theorem five_limb_addends_fit (a b c d e : Nat)
    (ha : a < radix) (hb : b < radix) (hc : c < radix)
    (hd : d < radix) (he : e < radix) :
    (a + b + c + d + e) / radix ≤ 4 ∧
      a + b + c + d + e + 4 < 2^53 := by
  unfold radix at *
  constructor <;> omega

theorem final_round_additions_fit (firstHigh secondHigh savedHigh carry : Nat)
    (firstFits : firstHigh < 5 * radix) (secondFits : secondHigh < 2 * radix)
    (savedFits : savedHigh < radix) (carryFits : carry ≤ 1) :
    firstHigh + secondHigh + carry < 2^53 ∧
      firstHigh + savedHigh + carry < 2^53 := by
  unfold radix at *
  constructor <;> omega

#print axioms rotations
#print axioms shifts
#print axioms limb_carry
#print axioms five_limb_addends_fit
#print axioms final_round_additions_fit

end Abc.Spec.Sha512SplitWord
