namespace Abc.Sha512.CLength

def limbBase : Nat := 2^64
def maxHigh : Nat := 2^61
def lowAfter (low count : Nat) : Nat := (low + count) % limbBase
def carry (low count : Nat) : Nat := if lowAfter low count < low then 1 else 0
def highAfter (high low count : Nat) : Nat := high + carry low count
def asNat (high low : Nat) : Nat := high * limbBase + low

theorem carry_matches_division (low count : Nat) (lowFits : low < limbBase)
    (countFits : count < limbBase) :
    carry low count = (low + count) / limbBase := by
  unfold carry lowAfter limbBase at *
  split <;> omega

theorem update_exact (high low count : Nat) (lowFits : low < limbBase)
    (countFits : count < limbBase) :
    asNat (highAfter high low count) (lowAfter low count) = asNat high low + count := by
  unfold asNat highAfter lowAfter
  rw [carry_matches_division low count lowFits countFits]
  unfold limbBase at *
  omega

theorem guard_exact (high low count : Nat) (lowFits : low < limbBase)
    (countFits : count < limbBase) :
    highAfter high low count < maxHigh ↔ (asNat high low + count) * 8 < 2^128 := by
  rw [← update_exact high low count lowFits countFits]
  unfold asNat maxHigh lowAfter limbBase
  omega

def update (high low count : Nat) : Bool × Nat × Nat :=
  if highAfter high low count < maxHigh
  then (true, highAfter high low count, lowAfter low count)
  else (false, high, low)

theorem reject_keeps_lengths (high low count : Nat) (lowFits : low < limbBase)
    (countFits : count < limbBase) (tooLong : 2^128 ≤ (asNat high low + count) * 8) :
    update high low count = (false, high, low) := by
  unfold update
  apply if_neg
  rw [guard_exact high low count lowFits countFits]
  omega

def wordsAfter (high low count : BitVec 64) : BitVec 64 × BitVec 64 :=
  let nextLow := low + count
  (high + (if nextLow < low then 1 else 0), nextLow)

theorem words_match_model (high low count : BitVec 64) (admitted : high.toNat < maxHigh) :
    let result := wordsAfter high low count
    (result.1.toNat, result.2.toNat) =
      (highAfter high.toNat low.toNat count.toNat, lowAfter low.toNat count.toNat) := by
  have lowWord : (low + count).toNat = lowAfter low.toNat count.toNat := by
    simp [BitVec.toNat_add, lowAfter, limbBase]
  have test : low + count < low ↔ lowAfter low.toNat count.toNat < low.toNat := by
    change (low + count).toNat < low.toNat ↔ _
    rw [lowWord]
  unfold wordsAfter highAfter carry
  simp only [lowWord, test]
  split
  · have h : (high + 1).toNat = high.toNat + 1 := by
      rw [BitVec.toNat_add]
      change (high.toNat + 1) % 2^64 = high.toNat + 1
      apply Nat.mod_eq_of_lt
      unfold maxHigh at admitted
      omega
    rw [h]
  · simp

#print axioms carry_matches_division
#print axioms update_exact
#print axioms guard_exact
#print axioms reject_keeps_lengths
#print axioms words_match_model

end Abc.Sha512.CLength
