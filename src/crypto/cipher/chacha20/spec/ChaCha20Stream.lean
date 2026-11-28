import ChaCha20Counter
import ChaCha20QuarterRound

namespace Abc.Spec.ChaCha20

local instance (counter length : Nat) : Decidable (admissible counter length) :=
  inferInstanceAs (Decidable (blockCount length ≤ counterDomain - counter))

/-- Logical position of the next byte in a 64-byte block traversal. -/
def streamPosition : Nat → Nat × Fin 64
  | 0 => (0, 0)
  | index + 1 =>
    let (block, offset) := streamPosition index
    if room : offset.val + 1 < 64 then (block, ⟨offset.val + 1, room⟩)
    else (block + 1, 0)

/-- A forward block traversal has exactly the quotient and remainder addresses
of the independent RFC specification, including just after a block ends. -/
theorem stream_position_exact (index : Nat) :
    streamPosition index = (index / 64, ⟨index % 64, Nat.mod_lt _ (by decide)⟩) := by
  induction index with
  | zero => rfl
  | succ index ih =>
    simp only [streamPosition, ih]
    split <;> rename_i room
    · congr 1
      · omega
      · apply Fin.ext
        simp only
        omega
    · congr 1
      · omega
      · apply Fin.ext
        simp only [Fin.val_zero]
        omega

/-- Offset and count arithmetic for every actual byte in an admitted input. -/
theorem stream_counter_in_range (counter : Word) {length : Nat}
    (admitted : admissible counter.toNat length) (index : Fin length) :
    counter.toNat + index.val / 64 < counterDomain := by
  apply counter_never_wraps counter.toNat length (index.val / 64) counter.isLt admitted
  have bound := index.isLt
  unfold blockCount
  omega

/-- The quotient/remainder form of ceiling division agrees with the block
count, including zero bytes and exact multiples of 64. -/
theorem stream_count_exact (length : Nat) :
    length / 64 + (if length % 64 = 0 then 0 else 1) = blockCount length := by
  unfold blockCount
  split <;> omega

private def xorAt (provider : Word → Bytes 64) (counter : Word) (index : Nat) (byte : Byte) : Byte :=
  let (block, offset) := streamPosition index
  byte ^^^ provider (counter + BitVec.ofNat 32 block) offset

/-- Sequential logical writes to the caller buffer. An address outside the
fixed-length view never matches a write. -/
def writePrefix (provider : Word → Bytes 64) (counter : Word)
    {length : Nat} (input : Bytes length) : Nat → Bytes length
  | 0 => input
  | amount + 1 =>
    let before := writePrefix provider counter input amount
    fun i => if i.val = amount then xorAt provider counter i.val (before i) else before i

/-- Every prefix transforms exactly the bytes already traversed and preserves
the untouched suffix of the caller buffer. -/
theorem stream_write_prefix (provider : Word → Bytes 64) (counter : Word)
    {length : Nat} (input : Bytes length) (amount : Nat) (i : Fin length) :
    writePrefix provider counter input amount i =
      if i.val < amount then xorAt provider counter i.val (input i) else input i := by
  induction amount with
  | zero => simp [writePrefix]
  | succ amount ih =>
    by_cases address : i.val = amount
    · simp [writePrefix, address, ih]
    · have previously : i.val < amount + 1 ↔ i.val < amount := by omega
      simp [writePrefix, address, ih, previously]

/-- A block-provider model of the byte writes: increment the byte cursor,
advance the block at offset 64, and reject before the first write. The Boolean
tracks the return status, while the byte view records the resulting input. -/
def chunkedTransform (provider : Word → Bytes 64) (counter : Word)
    {length : Nat} (input : Bytes length) : Bool × Bytes length :=
  if admissible counter.toNat length then
    (true, writePrefix provider counter input length)
  else (false, input)

/-- RFC 8439 §2.4.1 by absolute byte address, with explicit exhaustion handling.
Both the last full block and a final partial block use the same formula. -/
def streamTransform (key : Bytes 32) (nonce : Bytes 12) (counter : Word)
    {length : Nat} (input : Bytes length) : Bool × Bytes length :=
  if counter.toNat + blockCount length ≤ counterDomain then
    (true, fun byte => input byte ^^^
      blockBytes key nonce (BitVec.ofNat 32 (counter.toNat + byte.val / 64))
        ⟨byte.val % 64, Nat.mod_lt _ (by decide)⟩)
  else (false, input)

private theorem admissible_iff_sum (counter : Word) (length : Nat) :
    admissible counter.toNat length ↔ counter.toNat + blockCount length ≤ counterDomain := by
  have bound : counter.toNat < counterDomain := counter.isLt
  unfold admissible
  omega

/-- The guard is exact: a message is accepted precisely when every actual byte
can be assigned its counter without wrapping. -/
theorem stream_guard_exact (counter : Word) (length : Nat) :
    admissible counter.toNat length ↔
      ∀ byte : Fin length, counter.toNat + byte.val / 64 < counterDomain := by
  constructor
  · exact fun admitted => stream_counter_in_range counter admitted
  · intro safe
    apply (admissible_iff_sum counter length).mpr
    by_cases empty : length = 0
    · have bound : counter.toNat < counterDomain := counter.isLt
      simp only [empty, show blockCount 0 = 0 by decide, Nat.add_zero]
      omega
    · have last : length - 1 < length := by omega
      have bound := safe ⟨length - 1, last⟩
      change counter.toNat + (length - 1) / 64 < counterDomain at bound
      unfold blockCount
      omega

private theorem bitvec_index_sum (counter : Word) (index : Nat) :
    counter + BitVec.ofNat 32 index = BitVec.ofNat 32 (counter.toNat + index) := by
  apply BitVec.eq_of_toNat_eq
  simp only [BitVec.toNat_add, BitVec.toNat_ofNat]
  omega

/-- The complete chunked stream model agrees with the byte-indexed RFC model
for every finite input, including all rejected lengths and all output bytes. -/
theorem chunked_stream_refines (key : Bytes 32) (nonce : Bytes 12) (counter : Word)
    {length : Nat} (input : Bytes length) :
    chunkedTransform (blockBytes key nonce) counter input = streamTransform key nonce counter input := by
  unfold chunkedTransform streamTransform
  by_cases h : admissible counter.toNat length
  · simp only [h, (admissible_iff_sum counter length).mp h, if_true, Prod.mk.injEq, true_and]
    funext byte
    simp only [stream_write_prefix, if_pos byte.isLt, xorAt, stream_position_exact, bitvec_index_sum]
  · have rejected := mt (admissible_iff_sum counter length).mpr h
    simp only [h, rejected, if_false]

/-- At the stream-model boundary, a failed preflight returns the unchanged
caller buffer, as equality of every byte. -/
theorem stream_rejection_preserves (provider : Word → Bytes 64) (counter : Word)
    {length : Nat} (input : Bytes length) (exhausted : ¬ admissible counter.toNat length) :
    chunkedTransform provider counter input = (false, input) := by
  simp [chunkedTransform, exhausted]

/-- Applying the RFC transform twice at the same initial counter recovers
the original bytes when the counter range is admitted. -/
theorem stream_involution (key : Bytes 32) (nonce : Bytes 12) (counter : Word)
    {length : Nat} (input : Bytes length) (admitted : admissible counter.toNat length) :
    streamTransform key nonce counter (streamTransform key nonce counter input).2 = (true, input) := by
  simp only [streamTransform, (admissible_iff_sum counter length).mp admitted, if_true, Prod.mk.injEq,
    true_and]
  funext byte
  simp only [BitVec.xor_assoc, BitVec.xor_self, BitVec.xor_zero]

#print axioms stream_position_exact
#print axioms stream_counter_in_range
#print axioms stream_count_exact
#print axioms stream_write_prefix
#print axioms stream_guard_exact
#print axioms chunked_stream_refines
#print axioms stream_rejection_preserves
#print axioms stream_involution

end Abc.Spec.ChaCha20
