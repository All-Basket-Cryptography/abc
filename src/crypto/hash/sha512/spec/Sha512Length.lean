namespace Abc.Spec.Sha512

def maximumBytes : Nat := (2^128 - 1) / 8
def zeroBytes (length : Nat) : Nat := (239 - length % 128) % 128

theorem guard_exact (total incoming : Nat) (bounded : total ≤ maximumBytes) :
    incoming ≤ maximumBytes - total ↔ (total + incoming) * 8 < 2^128 := by
  unfold maximumBytes at *
  omega

theorem padded_block_multiple (length : Nat) :
    (length + 1 + zeroBytes length + 16) % 128 = 0 := by
  unfold zeroBytes
  omega

theorem two_blocks_iff (tail : Nat) (within : tail < 128) :
    128 < tail + 1 + zeroBytes tail + 16 ↔ 112 ≤ tail := by
  unfold zeroBytes
  omega

#print axioms guard_exact
#print axioms padded_block_multiple
#print axioms two_blocks_iff

end Abc.Spec.Sha512
