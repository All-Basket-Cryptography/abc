import Sha256Spec

namespace Abc.Spec.HmacSha256

open Abc.Spec.Sha256 (Message)

inductive Error where
  | keyTooLong
  | messageTooLong
  deriving DecidableEq, Repr

/-- RFC 2104 § 2 uses the input key directly up to one SHA-256 block,
    then uses its full SHA-256 digest. Pad either key material to one block. -/
def zeroPad (material : Message) : Message :=
  material ++ List.replicate (64 - material.length) 0

def normalizeKey (key : Message) : Option Message := do
  let material ← if key.length ≤ 64 then some key else Sha256.digest key
  some (zeroPad material)

def innerPad (keyBlock : Message) : Message := keyBlock.map (fun byte => byte ^^^ 0x36)

def outerPad (keyBlock : Message) : Message := keyBlock.map (fun byte => byte ^^^ 0x5c)

/-- The inner hash includes the entire 64-byte pad before the message. -/
def messageAllowed (length : Nat) : Prop := Sha256.byteLengthAllowed (64 + length)

instance (length : Nat) : Decidable (messageAllowed length) :=
  inferInstanceAs (Decidable (Sha256.byteLengthAllowed (64 + length)))

/-- RFC 2104 § 2 with SHA-256 and the full, 32-byte tag of RFC 4231.
    A key outside the underlying SHA-256 domain is rejected first. -/
def authenticate (key message : Message) : Except Error Message :=
  match normalizeKey key with
  | none => .error .keyTooLong
  | some keyBlock =>
    match Sha256.digest (innerPad keyBlock ++ message) with
    | none => .error .messageTooLong
    | some innerDigest =>
      match Sha256.digest (outerPad keyBlock ++ innerDigest) with
      | none => .error .messageTooLong
      | some tag => .ok tag

@[simp] theorem innerPad_length (keyBlock : Message) : (innerPad keyBlock).length = keyBlock.length :=
  List.length_map _

@[simp] theorem outerPad_length (keyBlock : Message) : (outerPad keyBlock).length = keyBlock.length :=
  List.length_map _

theorem sha256_digest_length {message hash : Message} (success : Sha256.digest message = some hash) :
    hash.length = 32 := by
  have encodeLength (state : Sha256.State) : (Sha256.encode state).length = 32 := rfl
  unfold Sha256.digest at success
  split at success
  · cases success
    exact encodeLength _
  · contradiction

theorem sha256_digest_accepted {message : Message} (allowed : Sha256.byteLengthAllowed message.length) :
    ∃ hash, Sha256.digest message = some hash ∧ hash.length = 32 := by
  have result : ∃ hash, Sha256.digest message = some hash := by
    rw [Sha256.digest, if_pos allowed]
    exact ⟨_, rfl⟩
  obtain ⟨hash, success⟩ := result
  exact ⟨hash, success, sha256_digest_length success⟩

theorem normalizeKey_accepted {key : Message} (allowed : Sha256.byteLengthAllowed key.length) :
    ∃ keyBlock, normalizeKey key = some keyBlock ∧ keyBlock.length = 64 := by
  unfold normalizeKey
  split
  · rename_i short
    exact ⟨_, rfl, by simp [zeroPad]; omega⟩
  · obtain ⟨hash, hashed, length⟩ := sha256_digest_accepted allowed
    rw [hashed]
    exact ⟨zeroPad hash, rfl, by simp [zeroPad, length]⟩

theorem normalizeKey_rejected {key : Message} (rejected : ¬ Sha256.byteLengthAllowed key.length) :
    normalizeKey key = none := by
  have long : ¬ key.length ≤ 64 := by
    unfold Sha256.byteLengthAllowed at rejected
    omega
  simp [normalizeKey, long, Sha256.digest, rejected]

theorem authenticate_key_rejected {key message : Message} (rejected : ¬ Sha256.byteLengthAllowed key.length) :
    authenticate key message = .error .keyTooLong := by
  simp only [authenticate, normalizeKey_rejected rejected]

theorem authenticate_message_rejected {key message : Message} (keyAllowed : Sha256.byteLengthAllowed key.length)
    (rejected : ¬ messageAllowed message.length) : authenticate key message = .error .messageTooLong := by
  obtain ⟨keyBlock, normalized, blockLength⟩ := normalizeKey_accepted keyAllowed
  have innerRejected : ¬ Sha256.byteLengthAllowed (innerPad keyBlock ++ message).length := by
    simpa only [List.length_append, innerPad_length, blockLength, messageAllowed] using rejected
  simp only [authenticate, normalized, Sha256.digest, if_neg innerRejected]

theorem authenticate_accepted {key message : Message} (keyAllowed : Sha256.byteLengthAllowed key.length)
    (messageFits : messageAllowed message.length) :
    ∃ tag, authenticate key message = .ok tag ∧ tag.length = 32 := by
  obtain ⟨keyBlock, normalized, blockLength⟩ := normalizeKey_accepted keyAllowed
  have innerFits : Sha256.byteLengthAllowed (innerPad keyBlock ++ message).length := by
    simpa only [List.length_append, innerPad_length, blockLength, messageAllowed] using messageFits
  obtain ⟨innerDigest, innerEq, innerLength⟩ := sha256_digest_accepted innerFits
  have outerFits : Sha256.byteLengthAllowed (outerPad keyBlock ++ innerDigest).length := by
    simp only [List.length_append, outerPad_length, blockLength, innerLength]
    decide
  obtain ⟨tag, outerEq, tagLength⟩ := sha256_digest_accepted outerFits
  exact ⟨tag, by simp only [authenticate, normalized, innerEq, outerEq], tagLength⟩

/-- The total tag expression is used only with proven valid inputs. -/
def tag (key message : Message) : Message :=
  match authenticate key message with
  | .ok result => result
  | .error _ => []

theorem authenticate_eq_ok {key message : Message} (keyAllowed : Sha256.byteLengthAllowed key.length)
    (messageFits : messageAllowed message.length) : authenticate key message = .ok (tag key message) := by
  obtain ⟨result, success, _⟩ := authenticate_accepted keyAllowed messageFits
  simp only [tag, success]

theorem tag_length {key message : Message} (keyAllowed : Sha256.byteLengthAllowed key.length)
    (messageFits : messageAllowed message.length) : (tag key message).length = 32 := by
  obtain ⟨result, success, length⟩ := authenticate_accepted keyAllowed messageFits
  simpa only [tag, success] using length

end Abc.Spec.HmacSha256
