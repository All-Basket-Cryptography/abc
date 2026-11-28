import ChaCha20QuarterRound

namespace Abc.Spec.ChaCha20.WordOutput

/-- Packed little-endian word XOR gives the bytewise RFC stream XOR. -/
theorem word_xor_refines_bytes (message stream : State) (index : Fin 64) :
    serializeBytes (fun lane => message lane ^^^ stream lane) index =
      serializeBytes message index ^^^ serializeBytes stream index := by
  simpa only [serializeBytes] using BitVec.extractLsb'_xor

/-- The unsigned shift and low-byte store used for a trailing partial word
select exactly the byte used by RFC little-endian serialization. -/
theorem tail_shift_refines_byte (word : Word) (lane : Fin 4) :
    ((word >>> (8 * lane.val)).setWidth 8) = word.extractLsb' (8 * lane.val) 8 :=
  BitVec.setWidth_ushiftRight_eq_extractLsb

theorem full_word_address (size : Nat) (lane : Fin (size / 4)) :
    4 * lane.val + 3 < size := by
  have bound := lane.isLt
  omega

theorem tail_word_address {size index : Nat} (inTail : 4 * (size / 4) ≤ index) (inView : index < size) :
    index / 4 = size / 4 ∧ index % 4 = index - 4 * (size / 4) := by
  omega

/-- Each feed-forward sum is below the exact-integer range of binary64.
The word XOR and the tail shift use its low 32 bits. -/
theorem feed_forward_sum_lt (left right : Word) :
    left.toNat + right.toNat < 2 ^ 33 := by
  have first := left.isLt
  have second := right.isLt
  omega

#print axioms word_xor_refines_bytes
#print axioms tail_shift_refines_byte
#print axioms full_word_address
#print axioms tail_word_address
#print axioms feed_forward_sum_lt

end Abc.Spec.ChaCha20.WordOutput
