import HmacSpec

namespace Abc.Spec.HkdfSha256

open Sha256 (Byte Message byteLengthAllowed)

inductive Error where
  | saltTooLong
  | inputTooLong
  | prkTooShort
  | prkTooLong
  | infoTooLong
  | outputTooLong
  deriving DecidableEq, Repr

def tagBytes : Nat := 32

def maximumOutput : Nat := 255 * tagBytes

def blockCount (length : Nat) : Nat := (length + tagBytes - 1) / tagBytes

-- RFC 5869 § 2.2. An absent salt supplies HashLen zero octets.
def extract (salt : Option Message) (input : Message) : Except Error Message :=
  match HmacSha256.authenticate (salt.getD (List.replicate tagBytes 0)) input with
  | .ok prk => .ok prk
  | .error .keyTooLong => .error .saltTooLong
  | .error .messageTooLong => .error .inputTooLong

-- RFC 5869 § 2.3. T(0) is empty, and the counter occupies one octet.
def block (prk info : Message) : Nat → Message
  | 0 => []
  | i + 1 => HmacSha256.tag prk (block prk info i ++ info ++ [BitVec.ofNat 8 (i + 1)])

def material (prk info : Message) : Nat → Message
  | 0 => []
  | i + 1 => material prk info i ++ block prk info (i + 1)

def expandMaterial (prk info : Message) (length : Nat) : Message :=
  (material prk info (blockCount length)).take length

/-- The largest HMAC message for this expansion has the counter byte and,
    when there is a second block, the whole preceding tag. -/
def infoOverhead (outputLength : Nat) : Nat :=
  if tagBytes < outputLength then tagBytes + 1 else 1

def infoAllowed (infoLength outputLength : Nat) : Prop :=
  byteLengthAllowed (64 + infoLength + infoOverhead outputLength)

instance (infoLength outputLength : Nat) : Decidable (infoAllowed infoLength outputLength) :=
  inferInstanceAs (Decidable (byteLengthAllowed _))

/-- Preflight checks exactly match the public Rust API's error priority. -/
def validateExpansion (prkLength infoLength outputLength : Nat) : Except Error Unit :=
  if prkLength < tagBytes then .error .prkTooShort
  else if !decide (byteLengthAllowed prkLength) then .error .prkTooLong
  else if maximumOutput < outputLength then .error .outputTooLong
  else if outputLength = 0 then .ok ()
  else if !decide (infoAllowed infoLength outputLength) then .error .infoTooLong
  else .ok ()

def expand (prk info : Message) (length : Nat) : Except Error Message := do
  validateExpansion prk.length info.length length
  return expandMaterial prk info length

def derive (salt : Option Message) (input info : Message) (length : Nat) : Except Error Message := do
  let prk ← extract salt input
  expand prk info length

structure ValidExpansion (prkLength infoLength outputLength : Nat) : Prop where
  prkMinimum : tagBytes ≤ prkLength
  prkAllowed : byteLengthAllowed prkLength
  outputMaximum : outputLength ≤ maximumOutput
  infoWithinDomain : outputLength ≠ 0 → infoAllowed infoLength outputLength

theorem validateExpansion_eq_ok_iff (prkLength infoLength outputLength : Nat) :
    validateExpansion prkLength infoLength outputLength = .ok () ↔
      ValidExpansion prkLength infoLength outputLength := by
  unfold validateExpansion
  by_cases short : prkLength < tagBytes
  · simp [short]
    intro valid
    exact (Nat.not_lt_of_ge valid.prkMinimum) short
  have longEnough := Nat.le_of_not_gt short
  by_cases keyAllowed : byteLengthAllowed prkLength
  · by_cases outputLong : maximumOutput < outputLength
    · simp [short, keyAllowed, outputLong]
      intro valid
      exact (Nat.not_lt_of_ge valid.outputMaximum) outputLong
    have outputAllowed := Nat.le_of_not_gt outputLong
    by_cases zero : outputLength = 0
    · simp [short, keyAllowed, zero]
      exact ⟨longEnough, keyAllowed, by omega, by simp⟩
    by_cases info : infoAllowed infoLength outputLength
    · simp [short, keyAllowed, outputLong, zero, info]
      exact ⟨longEnough, keyAllowed, outputAllowed, fun _ => info⟩
    · simp [short, keyAllowed, outputLong, zero, info]
      intro valid
      exact info (valid.infoWithinDomain zero)
  · simp [short, keyAllowed]
    intro valid
    exact keyAllowed valid.prkAllowed

theorem blockCount_zero : blockCount 0 = 0 := rfl

theorem blockCount_le_255 (length : Nat) (bounded : length ≤ maximumOutput) :
    blockCount length ≤ 255 := by
  simp only [maximumOutput, tagBytes] at bounded
  simp only [blockCount, tagBytes]
  omega

theorem blockCount_le_iff (length count : Nat) :
    blockCount length ≤ count ↔ length ≤ tagBytes * count := by
  simp only [blockCount, tagBytes]
  omega

theorem blockCount_pos (length : Nat) (nonzero : length ≠ 0) : 0 < blockCount length := by
  have := (blockCount_le_iff length 0)
  simp at this
  omega

theorem expandMaterial_zero (prk info : Message) : expandMaterial prk info 0 = [] := rfl

/-- When an iteration needs a preceding tag, the requested output spans two or more blocks. -/
theorem multiple_blocks_of_counter (length counter : Nat)
    (later : 1 < counter) (within : counter ≤ blockCount length) : tagBytes < length := by
  by_cases small : length ≤ tagBytes
  · have one := (blockCount_le_iff length 1).mpr (by simpa using small)
    omega
  · omega

theorem message_allowed_of_info (infoLength outputLength previousLength : Nat)
    (within : infoAllowed infoLength outputLength)
    (bound : previousLength + 1 ≤ infoOverhead outputLength) :
    HmacSha256.messageAllowed (previousLength + infoLength + 1) := by
  change 8 * (64 + infoLength + infoOverhead outputLength) < 18446744073709551616 at within
  change 8 * (64 + (previousLength + infoLength + 1)) < 18446744073709551616
  omega

theorem block_length (prk info : Message) (length count : Nat)
    (valid : ValidExpansion prk.length info.length length)
    (positive : 0 < count) (within : count ≤ blockCount length) :
    (block prk info count).length = tagBytes := by
  induction count with
  | zero => omega
  | succ i smaller =>
    have nonzero : length ≠ 0 := by
      intro empty
      rw [empty, blockCount_zero] at within
      omega
    have infoBound := valid.infoWithinDomain nonzero
    have bound : (block prk info i).length + 1 ≤ infoOverhead length := by
      cases i with
      | zero =>
        simp only [block, List.length_nil, Nat.zero_add, infoOverhead]
        split <;> simp [tagBytes]
      | succ i =>
        have multi := multiple_blocks_of_counter length (i + 1 + 1) (by omega) within
        rw [smaller (by omega) (by omega), infoOverhead, if_pos multi]
        exact Nat.le_refl _
    simp only [block, tagBytes]
    apply HmacSha256.tag_length valid.prkAllowed
    simpa [Nat.add_assoc] using
      message_allowed_of_info info.length length (block prk info i).length infoBound bound

theorem block_message_allowed (prk info : Message) (length i : Nat)
    (valid : ValidExpansion prk.length info.length length) (within : i + 1 ≤ blockCount length) :
    HmacSha256.messageAllowed (block prk info i ++ info ++ [BitVec.ofNat 8 (i + 1)]).length := by
  have nonzero : length ≠ 0 := by
    intro empty
    rw [empty, blockCount_zero] at within
    omega
  simp only [List.length_append, List.length_singleton]
  apply message_allowed_of_info _ _ _ (valid.infoWithinDomain nonzero)
  cases i with
  | zero =>
    simp only [block, List.length_nil, Nat.zero_add, infoOverhead]
    split <;> simp [tagBytes]
  | succ i =>
    have multi := multiple_blocks_of_counter length (i + 1 + 1) (by omega) within
    rw [block_length prk info length _ valid (by omega) (by omega), infoOverhead, if_pos multi]
    exact Nat.le_refl _

theorem material_length (prk info : Message) (length count : Nat)
    (valid : ValidExpansion prk.length info.length length) (within : count ≤ blockCount length) :
    (material prk info count).length = tagBytes * count := by
  induction count with
  | zero => rfl
  | succ i smaller =>
    simp [material, smaller (by omega), block_length prk info length (i + 1) valid (by omega) within,
      Nat.mul_succ]

theorem expandMaterial_length (prk info : Message) (length : Nat)
    (valid : ValidExpansion prk.length info.length length) :
    (expandMaterial prk info length).length = length := by
  have covered := (blockCount_le_iff length (blockCount length)).mp (Nat.le_refl _)
  simp [expandMaterial, material_length prk info length _ valid (Nat.le_refl _), Nat.min_eq_left covered]

end Abc.Spec.HkdfSha256
