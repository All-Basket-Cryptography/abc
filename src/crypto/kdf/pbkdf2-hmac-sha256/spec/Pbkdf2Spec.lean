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

#print axioms iterate_eq_fold
#print axioms index_bound
#print axioms salt_index_domain
#print axioms prehash_preserves_material

end Abc.Spec.Pbkdf2
