import Init.Data.BitVec

namespace Abc.Spec.Aes256

abbrev Byte := BitVec 8

def mulX (a : Byte) : Byte := (a <<< 1) ^^^ (0x1b &&& (0 - (a >>> 7)))

def mulStep : Nat → Byte → Byte → Byte → Byte
  | 0, _, _, acc => acc
  | n + 1, a, b, acc =>
    mulStep n (mulX a) (b >>> 1) (acc ^^^ (a &&& (0 - (b &&& 1))))

def mul (a b : Byte) : Byte := mulStep 8 a b 0

def spreadSquare (x : Byte) : Byte :=
  let word := x.zeroExtend 16
  let split₁ := (word ||| (word <<< 4)) &&& 0x0f0f
  let split₂ := (split₁ ||| (split₁ <<< 2)) &&& 0x3333
  let spread := (split₂ ||| (split₂ <<< 1)) &&& 0x5555
  let upper₁ := spread >>> 8
  let folded := (spread &&& 0xff) ^^^ upper₁ ^^^ (upper₁ <<< 1) ^^^ (upper₁ <<< 3) ^^^ (upper₁ <<< 4)
  let upper₂ := folded >>> 8
  (folded ^^^ upper₂ ^^^ (upper₂ <<< 1) ^^^ (upper₂ <<< 3) ^^^ (upper₂ <<< 4)).truncate 8

set_option maxRecDepth 4096 in
set_option maxHeartbeats 3000000 in
theorem spread_square_matches_multiplication :
    ∀ i : Fin 256, let x := BitVec.ofNat 8 i.val
      spreadSquare x = mul x x := by
  decide

def inverse (x : Byte) : Byte :=
  let x2 := mul x x
  let x3 := mul x2 x
  let x6 := mul x3 x3
  let x7 := mul x6 x
  let x14 := mul x7 x7
  let x15 := mul x14 x
  let x30 := mul x15 x15
  let x60 := mul x30 x30
  let x120 := mul x60 x60
  let x127 := mul x120 x7
  mul x127 x127

def spreadInverse (x : Byte) : Byte :=
  let x2 := spreadSquare x
  let x3 := mul x2 x
  let x6 := spreadSquare x3
  let x7 := mul x6 x
  let x14 := spreadSquare x7
  let x15 := mul x14 x
  let x30 := spreadSquare x15
  let x60 := spreadSquare x30
  let x120 := spreadSquare x60
  let x127 := mul x120 x7
  spreadSquare x127

theorem spread_inverse_matches (x : Byte) : spreadInverse x = inverse x := by
  have squareMatches (word : Byte) : spreadSquare word = mul word word := by
    simpa using spread_square_matches_multiplication word.toFin
  simp only [spreadInverse, inverse, squareMatches]

def sbox (x : Byte) : Byte :=
  let y := inverse x
  y ^^^ y.rotateLeft 1 ^^^ y.rotateLeft 2 ^^^ y.rotateLeft 3 ^^^ y.rotateLeft 4 ^^^ 0x63

def inverseSbox (y : Byte) : Byte :=
  inverse (y.rotateLeft 1 ^^^ y.rotateLeft 3 ^^^ y.rotateLeft 6 ^^^ 0x05)

set_option maxRecDepth 4096 in
set_option maxHeartbeats 3000000 in
theorem substitution_bijective :
    ∀ i : Fin 256, let x := BitVec.ofNat 8 i.val
      inverseSbox (sbox x) = x ∧ sbox (inverseSbox x) = x := by
  decide

#print axioms substitution_bijective
#print axioms spread_square_matches_multiplication
#print axioms spread_inverse_matches

end Abc.Spec.Aes256
