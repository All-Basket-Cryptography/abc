namespace Abc.Spec.ChaCha20

def counterDomain : Nat := 2^32
def blockCount (length : Nat) : Nat := (length + 63) / 64
def admissible (counter length : Nat) : Prop :=
  blockCount length ≤ counterDomain - counter

theorem blocks_cover_length (length : Nat) :
    length ≤ blockCount length * 64 := by
  unfold blockCount
  omega

theorem counter_never_wraps (counter length index : Nat) (counterInRange : counter < counterDomain)
    (admitted : admissible counter length) (inBlocks : index < blockCount length) :
    counter + index < counterDomain := by
  unfold admissible at admitted
  omega

theorem last_counter_only_one_block (length : Nat) :
    admissible (counterDomain - 1) length ↔ length ≤ 64 := by
  unfold admissible counterDomain blockCount
  omega

#print axioms blocks_cover_length
#print axioms counter_never_wraps
#print axioms last_counter_only_one_block

end Abc.Spec.ChaCha20
