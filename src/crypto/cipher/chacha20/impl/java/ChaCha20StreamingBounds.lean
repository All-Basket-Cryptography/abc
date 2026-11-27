namespace Abc.Spec.ChaCha20JavaStream

def limit : Nat := 2 ^ 32

def remaining (next offset : Nat) : Nat :=
  (limit - next) * 64 + (64 - offset)

-- A refill reserves one block and makes its 64 bytes available.
theorem refill_preserves_remaining (next : Nat) (valid : next < limit) :
    next + 1 ≤ limit ∧ remaining next 64 = remaining (next + 1) 0 := by
  unfold remaining
  omega

-- A nonempty validated update may refill only with a representable counter.
theorem refill_counter_in_range (next : Nat) (count : Nat)
    (positive : 0 < count) (accepted : count ≤ remaining next 64) :
    next < limit := by
  unfold remaining at accepted
  omega

theorem consume_reduces_remaining (next offset count : Nat) (fits : offset + count ≤ 64) :
    remaining next (offset + count) + count = remaining next offset := by
  unfold remaining
  omega

theorem remaining_fits_long (next offset : Nat)
    (counterBound : next ≤ limit) (shape : 0 < next ∨ offset = 64) :
    remaining next offset ≤ 2 ^ 38 := by
  unfold remaining limit at *
  omega

#print axioms refill_preserves_remaining
#print axioms refill_counter_in_range
#print axioms consume_reduces_remaining
#print axioms remaining_fits_long

end Abc.Spec.ChaCha20JavaStream
