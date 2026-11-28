import Std

namespace Abc.Spec.Blake2b

/-- Complete blocks that can be compressed before the final byte is seen. -/
def nonfinalBlocks (length : Nat) : Nat := (length - 1) / 128

/-- The last block, including an exact 128-byte block, is held for finalization. -/
def pendingBytes (length : Nat) : Nat := length - 128 * nonfinalBlocks length

theorem buffer_layout (length : Nat) :
    128 * nonfinalBlocks length + pendingBytes length = length ∧
    pendingBytes length ≤ 128 ∧
    (length > 0 → pendingBytes length > 0) := by
  simp only [pendingBytes, nonfinalBlocks]
  omega

theorem one_block_pending (length : Nat) (fits : length ≤ 128) :
    nonfinalBlocks length = 0 ∧ pendingBytes length = length := by
  simp only [pendingBytes, nonfinalBlocks]
  omega

theorem exact_multiple_pending (count : Nat) (nonempty : 0 < count) :
    nonfinalBlocks (128 * count) = count - 1 ∧ pendingBytes (128 * count) = 128 := by
  simp only [pendingBytes, nonfinalBlocks]
  omega

end Abc.Spec.Blake2b
