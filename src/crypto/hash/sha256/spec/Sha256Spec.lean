import Abc.Foundation.Encoding

namespace Abc.Spec.Sha256

abbrev Byte := Abc.Foundation.Byte
abbrev Word := BitVec 32
abbrev Message := List Byte

structure State where
  a : Word
  b : Word
  c : Word
  d : Word
  e : Word
  f : Word
  g : Word
  h : Word

-- FIPS 180-4 §§ 3.1, 5.1.1. The byte API accepts the subset with byte-aligned length.
def byteLengthAllowed (bytes : Nat) : Prop := 8 * bytes < 2 ^ 64

instance (bytes : Nat) : Decidable (byteLengthAllowed bytes) :=
  inferInstanceAs (Decidable (8 * bytes < 2 ^ 64))

private def bigEndian := Abc.Foundation.bytesBigEndian

def padding (message : Message) : List Byte :=
  let zeroBytes := (119 - message.length % 64) % 64
  [0x80] ++ List.replicate zeroBytes 0 ++ bigEndian 8 (8 * message.length)

-- FIPS 180-4 §§ 3.2, 4.1.2. BitVec addition is modulo 2^32.
def pick (x y z : Word) : Word := (x &&& y) ^^^ ((~~~x) &&& z)
def majority (x y z : Word) : Word := (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)

def sumZero (x : Word) : Word := x.rotateRight 2 ^^^ x.rotateRight 13 ^^^ x.rotateRight 22
def sumOne (x : Word) : Word := x.rotateRight 6 ^^^ x.rotateRight 11 ^^^ x.rotateRight 25
def scheduleZero (x : Word) : Word := x.rotateRight 7 ^^^ x.rotateRight 18 ^^^ (x >>> 3)
def scheduleOne (x : Word) : Word := x.rotateRight 17 ^^^ x.rotateRight 19 ^^^ (x >>> 10)

-- FIPS 180-4 § 4.2.2.
def constants : Array Word := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

-- FIPS 180-4 § 5.3.3.
def initial : State :=
  ⟨0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19⟩

-- FIPS 180-4 §§ 5.2.1, 6.2.2(1). Each block begins with sixteen big-endian words.
def parseWord (bytes : List Byte) : Word :=
  BitVec.ofNat 32 (Abc.Foundation.decodeBigEndian bytes)

def messageSchedule (block : List Byte) : Array Word :=
  let words := ((List.range 16).map fun i => parseWord ((block.drop (4 * i)).take 4)).toArray
  (List.range 48).foldl (fun schedule i =>
    schedule.push (scheduleOne (schedule.getD (i + 14) 0) + schedule.getD (i + 9) 0
      + scheduleZero (schedule.getD (i + 1) 0) + schedule.getD i 0)) words

-- FIPS 180-4 § 6.2.2(2–4). Each round reads the same pre-round state for both temporaries.
def round (state : State) (constant word : Word) : State :=
  let first := state.h + sumOne state.e + pick state.e state.f state.g + constant + word
  let second := sumZero state.a + majority state.a state.b state.c
  ⟨first + second, state.a, state.b, state.c, state.d + first, state.e, state.f, state.g⟩

def addState (left right : State) : State :=
  ⟨left.a + right.a, left.b + right.b, left.c + right.c, left.d + right.d,
    left.e + right.e, left.f + right.f, left.g + right.g, left.h + right.h⟩

def compress (state : State) (block : List Byte) : State :=
  let schedule := messageSchedule block
  let final := (List.range 64).foldl
    (fun work i => round work (constants.getD i 0) (schedule.getD i 0)) state
  addState state final

def encode (state : State) : List Byte :=
  [state.a, state.b, state.c, state.d, state.e, state.f, state.g, state.h].flatMap
    (fun word => bigEndian 4 word.toNat)

/-- SHA-256 over the byte-aligned domain. An out-of-range message has no digest. -/
def digest (message : Message) : Option (List Byte) :=
  if byteLengthAllowed message.length then
    let padded := message ++ padding message
    let final := (List.range (padded.length / 64)).foldl
      (fun state i => compress state ((padded.drop (i * 64)).take 64)) initial
    some (encode final)
  else none

/-- Streaming semantics are a pure trace of the message bytes in update order. -/
structure Stream where
  message : Message

def Stream.init : Stream := ⟨[]⟩

def Stream.update (state : Stream) (chunk : Message) : Option Stream :=
  if byteLengthAllowed (state.message.length + chunk.length) then
    some ⟨state.message ++ chunk⟩
  else none

def Stream.finalize (state : Stream) : Option (List Byte) := digest state.message

theorem Stream.update_within_domain (state : Stream) (chunk : Message)
    (allowed : byteLengthAllowed (state.message.length + chunk.length)) :
    state.update chunk = some ⟨state.message ++ chunk⟩ := by
  simp [Stream.update, allowed]

theorem Stream.rejects_out_of_domain (state : Stream) (chunk : Message)
    (disallowed : ¬ byteLengthAllowed (state.message.length + chunk.length)) :
    state.update chunk = none := by
  simp [Stream.update, disallowed]

theorem Stream.finalize_after_update (state : Stream) (chunk : Message)
    (allowed : byteLengthAllowed (state.message.length + chunk.length)) :
    (state.update chunk).bind Stream.finalize = digest (state.message ++ chunk) := by
  rw [state.update_within_domain chunk allowed]
  rfl

end Abc.Spec.Sha256
