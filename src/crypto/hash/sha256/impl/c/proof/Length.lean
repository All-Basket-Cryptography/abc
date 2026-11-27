import Lean

namespace Abc.CSha256

def maxMessageBytes : Nat := 2305843009213693951

def chunkBytes (remaining : Nat) : Nat := min remaining 4294967295

/-- The subtraction guard used before any update has the SHA-256 byte domain. -/
theorem length_guard (current incoming : Nat) (valid : current ≤ maxMessageBytes) :
    incoming ≤ maxMessageBytes - current ↔ 8 * (current + incoming) < 2 ^ 64 := by
  unfold maxMessageBytes at valid ⊢
  change _ ↔ 8 * (current + incoming) < 18446744073709551616
  omega

/-- The bounded chunk passes through the upstream API's 32-bit argument exactly. -/
theorem chunk_cast (remaining : Nat) :
    (UInt32.ofNat (chunkBytes remaining)).toNat = chunkBytes remaining := by
  rw [UInt32.toNat_ofNat']
  apply Nat.mod_eq_of_lt
  have bound : chunkBytes remaining ≤ 4294967295 := Nat.min_le_right _ _
  change chunkBytes remaining < 4294967296
  omega

/-- Every iteration with remaining input makes progress. -/
theorem chunk_progress (remaining : Nat) (nonempty : 0 < remaining) :
    0 < chunkBytes remaining ∧ remaining - chunkBytes remaining < remaining := by
  unfold chunkBytes
  omega

/-- The accepted counter and capacity stay valid after each chunk. -/
theorem chunk_preserves_capacity (current remaining : Nat)
    (valid : current ≤ maxMessageBytes) (fits : remaining ≤ maxMessageBytes - current) :
    current + chunkBytes remaining ≤ maxMessageBytes ∧
      remaining - chunkBytes remaining ≤ maxMessageBytes - (current + chunkBytes remaining) ∧
      (current + chunkBytes remaining) + (remaining - chunkBytes remaining) = current + remaining := by
  have fitsRemaining : chunkBytes remaining ≤ remaining := Nat.min_le_left _ _
  omega

#print axioms length_guard
#print axioms chunk_cast
#print axioms chunk_progress
#print axioms chunk_preserves_capacity

end Abc.CSha256
