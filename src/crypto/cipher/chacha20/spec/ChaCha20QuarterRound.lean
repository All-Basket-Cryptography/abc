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

end Abc.Spec.ChaCha20
