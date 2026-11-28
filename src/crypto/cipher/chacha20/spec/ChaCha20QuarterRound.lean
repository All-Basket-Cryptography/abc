namespace Abc.Spec.ChaCha20

abbrev Word := BitVec 32
abbrev State := Fin 16 → Word

structure Words where
  a : Word
  b : Word
  c : Word
  d : Word
  deriving DecidableEq

private def halfRound (w : Words) (first second : Nat) : Words :=
  let a := w.a + w.b
  let d := (w.d ^^^ a).rotateLeft first
  let c := w.c + d
  let b := (w.b ^^^ c).rotateLeft second
  ⟨a, b, c, d⟩

/-- The four-word quarter round of RFC 8439, § 2.1. -/
def quarterRound (w : Words) : Words := halfRound (halfRound w 16 12) 8 7

/-- RFC 8439, § 2.2, places the four results back into the 16-word state. -/
def quarterRoundAt (state : State) (a b c d : Fin 16) : State :=
  let w := quarterRound ⟨state a, state b, state c, state d⟩
  fun i => if i = a then w.a else if i = b then w.b else if i = c then w.c
    else if i = d then w.d else state i

/-- The RFC 8439 § 2.1.1 known answer checked against the specification. -/
theorem rfcQuarterRound :
    quarterRound ⟨0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567⟩ =
      ⟨0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb⟩ := by
  decide

/-- A column round followed by a diagonal round (RFC 8439, § 2.3). -/
def doubleRound (state : State) : State :=
  let s1 := quarterRoundAt state 0 4 8 12
  let s2 := quarterRoundAt s1 1 5 9 13
  let s3 := quarterRoundAt s2 2 6 10 14
  let s4 := quarterRoundAt s3 3 7 11 15
  let s5 := quarterRoundAt s4 0 5 10 15
  let s6 := quarterRoundAt s5 1 6 11 12
  let s7 := quarterRoundAt s6 2 7 8 13
  quarterRoundAt s7 3 4 9 14

/-- Apply the specified double round repeatedly, in chronological order. -/
def repeatDouble : Nat → State → State
  | 0, state => state
  | n + 1, state => repeatDouble n (doubleRound state)

/-- The block counter occupies word 12 of the initial state. -/
def withCounter (state : State) (counter : Word) : State :=
  fun i => if i.val = 12 then counter else state i

/-- The RFC block function from input words to output words. -/
def blockWords (state : State) (counter : Word) : State :=
  let initial := withCounter state counter
  let transformed := repeatDouble 10 initial
  fun i => transformed i + initial i

abbrev Byte := BitVec 8
abbrev Bytes (n : Nat) := Fin n → Byte

/-- Interpret four bytes as an RFC 8439 little-endian state word. -/
def loadLe (a b c d : Byte) : Word := d ++ c ++ b ++ a

/-- RFC 8439 § 2.3 encodes the key and nonce into the initial state. -/
def initialFromBytes (key : Bytes 32) (nonce : Bytes 12) : State := fun lane =>
  match lane.val with
  | 0 => 0x61707865
  | 1 => 0x3320646e
  | 2 => 0x79622d32
  | 3 => 0x6b206574
  | 4 => loadLe (key 0) (key 1) (key 2) (key 3)
  | 5 => loadLe (key 4) (key 5) (key 6) (key 7)
  | 6 => loadLe (key 8) (key 9) (key 10) (key 11)
  | 7 => loadLe (key 12) (key 13) (key 14) (key 15)
  | 8 => loadLe (key 16) (key 17) (key 18) (key 19)
  | 9 => loadLe (key 20) (key 21) (key 22) (key 23)
  | 10 => loadLe (key 24) (key 25) (key 26) (key 27)
  | 11 => loadLe (key 28) (key 29) (key 30) (key 31)
  | 12 => 0
  | 13 => loadLe (nonce 0) (nonce 1) (nonce 2) (nonce 3)
  | 14 => loadLe (nonce 4) (nonce 5) (nonce 6) (nonce 7)
  | _ => loadLe (nonce 8) (nonce 9) (nonce 10) (nonce 11)

/-- Encode each output word from its least significant byte to its highest. -/
def serializeBytes (words : State) : Bytes 64 := fun index =>
  (words ⟨index.val / 4, by have h := index.isLt; omega⟩).extractLsb' (8 * (index.val % 4)) 8

/-- The complete block function of RFC 8439 § 2.3, from key and nonce to bytes. -/
def blockBytes (key : Bytes 32) (nonce : Bytes 12) (counter : Word) : Bytes 64 :=
  serializeBytes (blockWords (initialFromBytes key nonce) counter)

end Abc.Spec.ChaCha20
