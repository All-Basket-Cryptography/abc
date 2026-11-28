import HmacSpec

namespace Abc.Spec.Pbkdf2

open Abc.Spec.Sha256 (Byte Message byteLengthAllowed)

def hashLength : Nat := 32
def maximumIndex : Nat := 2^32 - 1
def maximumOutput : Nat := maximumIndex * hashLength
def blockCount (length : Nat) : Nat := (length + hashLength - 1) / hashLength

def indexBytes (index : Nat) : Message :=
  Abc.Foundation.bytesBigEndian 4 index

def xor (a b : Message) : Message := List.zipWith (· ^^^ ·) a b

/-- RFC 8018 § 5.2 defines U(1) as the PRF of salt and a big-endian index.
Each additional U value is the PRF of the previous value. -/
def successors (prf : Message → Message) : Nat → Message → List Message
  | 0, _ => []
  | n + 1, previous => prf previous :: successors prf n (prf previous)

def block (password salt : Message) (additionalRounds index : Nat) : Message :=
  let prf := Abc.Spec.HmacSha256.tag password
  let first := prf (salt ++ indexBytes index)
  (successors prf additionalRounds first).foldl xor first

def material (password salt : Message) (additionalRounds length : Nat) : Message :=
  ((List.range (blockCount length)).flatMap
    (fun index => block password salt additionalRounds (index + 1))).take length

/-- A rolling accumulator keeps only the previous U and the XOR of U values. -/
def iterate (prf : Message → Message) : Nat → Message → Message → Message
  | 0, _, accumulator => accumulator
  | n + 1, previous, accumulator =>
    let next := prf previous
    iterate prf n next (xor accumulator next)

theorem iterate_eq_fold (prf : Message → Message) (rounds : Nat) (previous accumulator : Message) :
    iterate prf rounds previous accumulator = (successors prf rounds previous).foldl xor accumulator := by
  induction rounds generalizing previous accumulator with
  | zero => rfl
  | succ n ih => exact ih (prf previous) (xor accumulator (prf previous))

theorem block_count_bound (length : Nat) (allowed : length ≤ maximumOutput) :
    blockCount length ≤ maximumIndex := by
  change (length + 31) / 32 ≤ 4294967295
  change length ≤ 4294967295 * 32 at allowed
  omega

theorem index_bound (length index : Nat) (allowed : length ≤ maximumOutput)
    (i : index < blockCount length) : index + 1 ≤ maximumIndex := by
  have bound := block_count_bound length allowed
  omega

theorem salt_index_domain (saltLength : Nat) (allowed : byteLengthAllowed (64 + saltLength + 4)) :
    byteLengthAllowed (64 + (saltLength + 4)) := by
  rw [← Nat.add_assoc]
  exact allowed

theorem long_password_normalization {password hash : Message}
    (long : 64 < password.length) (hashed : Abc.Spec.Sha256.digest password = some hash) :
    Abc.Spec.HmacSha256.normalizeKey hash = Abc.Spec.HmacSha256.normalizeKey password := by
  have short : hash.length ≤ 64 := by
    rw [Abc.Spec.HmacSha256.sha256_digest_length hashed]
    decide
  simp [Abc.Spec.HmacSha256.normalizeKey, short, Nat.not_le_of_gt long, hashed]

theorem prehash_preserves_material {password hash : Message}
    (long : 64 < password.length) (hashed : Abc.Spec.Sha256.digest password = some hash)
    (salt : Message) (rounds length : Nat) :
    material hash salt rounds length = material password salt rounds length := by
  have tags : Abc.Spec.HmacSha256.tag hash = Abc.Spec.HmacSha256.tag password := by
    funext input
    unfold Abc.Spec.HmacSha256.tag Abc.Spec.HmacSha256.authenticate
    rw [long_password_normalization long hashed]
  simp [material, block, tags]

/- The bounded, caller-owned output model follows the portable Rust control
flow. A block is produced and truncated before advancing to the next index. -/
inductive Error
  | passwordTooLong | saltTooLong | outputLength
  deriving DecidableEq

def maximumPassword : Nat := 2^61 - 1
def maximumSalt : Nat := maximumPassword - 64 - 4

def Accepted (password salt output : Nat) : Prop :=
  password ≤ maximumPassword ∧ salt ≤ maximumSalt ∧ 0 < output ∧ output ≤ maximumOutput

def validate (password salt output : Nat) : Option Error :=
  if password > maximumPassword then some .passwordTooLong
  else if salt > maximumSalt then some .saltTooLong
  else if output = 0 ∨ output > maximumOutput then some .outputLength
  else none

theorem valid_iff (password salt output : Nat) :
    validate password salt output = none ↔ Accepted password salt output := by
  unfold validate Accepted
  by_cases hp : password > maximumPassword <;> by_cases hs : salt > maximumSalt <;>
    by_cases ho : output = 0 ∨ output > maximumOutput <;>
    simp [hp, hs, ho] <;> omega

def blockModel (password salt : Message) (rounds index : Nat) : Message :=
  let prf := Abc.Spec.HmacSha256.tag password
  let first := prf (salt ++ indexBytes index)
  iterate prf rounds first first

theorem block_model_eq (password salt : Message) (rounds index : Nat) :
    blockModel password salt rounds index = block password salt rounds index := by
  simp only [blockModel, block, iterate_eq_fold]

def writeBlocks (makeBlock : Nat → Message) : Nat → Nat → Nat → Message
  | 0, _, _ => []
  | count + 1, index, remaining =>
      let bytes := makeBlock index
      bytes.take remaining ++ writeBlocks makeBlock count (index + 1) (remaining - bytes.length)

theorem write_blocks_eq_take (makeBlock : Nat → Message) (count index remaining : Nat) :
    writeBlocks makeBlock count index remaining =
      ((List.range' index count).flatMap makeBlock).take remaining := by
  induction count generalizing index remaining with
  | zero => simp [writeBlocks]
  | succ count ih =>
    rw [writeBlocks, List.range'_succ, List.flatMap_cons, List.take_append, ih]

theorem write_model_eq_material (password salt : Message) (rounds length : Nat) :
    writeBlocks (blockModel password salt rounds) (blockCount length) 1 length =
      material password salt rounds length := by
  rw [write_blocks_eq_take, List.range'_eq_map_range, List.flatMap_map]
  simp [material, block_model_eq, Nat.add_comm]

theorem iterate_length (prf : Message → Message) (rounds width : Nat) (previous acc : Message)
    (previousLength : previous.length = width) (accLength : acc.length = width)
    (fixedPrf : ∀ input : Message, input.length = width → (prf input).length = width) :
    (iterate prf rounds previous acc).length = width := by
  induction rounds generalizing previous acc with
  | zero => exact accLength
  | succ rounds ih =>
    simp only [iterate]
    have nextLength := fixedPrf previous previousLength
    apply ih (prf previous) (xor acc (prf previous)) nextLength
    simp [xor, accLength, nextLength]

theorem block_length {password salt : Message} (rounds index : Nat)
    (keyValid : password.length ≤ maximumPassword) (saltValid : salt.length ≤ maximumSalt) :
    (block password salt rounds index).length = hashLength := by
  have keyFits : byteLengthAllowed password.length := by
    unfold byteLengthAllowed maximumPassword at *
    omega
  have indexLength : (indexBytes index).length = 4 := by
    simp [indexBytes, Abc.Foundation.bytesBigEndian]
  have firstFits : Abc.Spec.HmacSha256.messageAllowed (salt ++ indexBytes index).length := by
    unfold Abc.Spec.HmacSha256.messageAllowed byteLengthAllowed
    simp only [List.length_append, indexLength]
    unfold maximumSalt maximumPassword at saltValid
    omega
  have first := Abc.Spec.HmacSha256.tag_length keyFits firstFits
  rw [← block_model_eq]
  unfold blockModel
  apply iterate_length _ _ _ _ _ first first
  intro input length
  apply Abc.Spec.HmacSha256.tag_length keyFits
  rw [length]
  decide

theorem flat_map_blocks_length (makeBlock : Nat → Message) (indices : List Nat) (width : Nat)
    (fixedBlock : ∀ index, (makeBlock index).length = width) :
    (indices.flatMap makeBlock).length = indices.length * width := by
  induction indices with
  | nil => simp
  | cons index rest ih => simp [fixedBlock, ih, Nat.add_mul, Nat.add_comm]

theorem material_length {password salt : Message} (rounds length : Nat)
    (keyValid : password.length ≤ maximumPassword) (saltValid : salt.length ≤ maximumSalt) :
    (material password salt rounds length).length = length := by
  unfold material
  rw [List.length_take, flat_map_blocks_length _ _ hashLength (fun i => block_length rounds (i+1) keyValid saltValid)]
  simp only [List.length_range]
  have fits : length ≤ blockCount length * hashLength := by
    change length ≤ (length + 31) / 32 * 32
    omega
  exact Nat.min_eq_left fits

def prehashPassword (password : Message) : Message :=
  if 64 < password.length then (Abc.Spec.Sha256.digest password).getD [] else password

theorem prehash_password_eq {password : Message} (keyValid : password.length ≤ maximumPassword)
    (salt : Message) (rounds length : Nat) :
    material (prehashPassword password) salt rounds length = material password salt rounds length := by
  by_cases long : 64 < password.length
  · have keyFits : byteLengthAllowed password.length := by
      unfold byteLengthAllowed maximumPassword at *
      omega
    obtain ⟨hash, hashed, _⟩ := Abc.Spec.HmacSha256.sha256_digest_accepted keyFits
    simpa [prehashPassword, long, hashed] using prehash_preserves_material long hashed salt rounds length
  · simp [prehashPassword, long]

def deriveModel (password salt : Message) (rounds : Nat) (output : Message) :
    Except Error Unit × Message :=
  match validate password.length salt.length output.length with
  | some reason => (.error reason, output)
  | none =>
    (.ok (), writeBlocks (blockModel (prehashPassword password) salt rounds)
      (blockCount output.length) 1 output.length)

theorem derive_model_success (password salt output : Message) (rounds : Nat)
    (valid : Accepted password.length salt.length output.length) :
    deriveModel password salt rounds output = (.ok (), material password salt rounds output.length) ∧
      (deriveModel password salt rounds output).2.length = output.length := by
  have success : deriveModel password salt rounds output = (.ok (), material password salt rounds output.length) := by
    simp only [deriveModel, (valid_iff _ _ _).mpr valid, write_model_eq_material,
      prehash_password_eq valid.1]
  exact ⟨success, by rw [success]; exact material_length rounds _ valid.1 valid.2.1⟩

theorem derive_model_failure (password salt output : Message) (rounds : Nat)
    (invalid : ¬ Accepted password.length salt.length output.length) :
    ∃ reason, deriveModel password salt rounds output = (.error reason, output) := by
  cases validation : validate password.length salt.length output.length with
  | none => exact False.elim (invalid ((valid_iff _ _ _).mp validation))
  | some reason => exact ⟨reason, by simp [deriveModel, validation]⟩

#print axioms iterate_eq_fold
#print axioms index_bound
#print axioms salt_index_domain
#print axioms prehash_preserves_material
#print axioms valid_iff
#print axioms block_model_eq
#print axioms write_model_eq_material
#print axioms block_length
#print axioms material_length
#print axioms derive_model_success
#print axioms derive_model_failure

end Abc.Spec.Pbkdf2
