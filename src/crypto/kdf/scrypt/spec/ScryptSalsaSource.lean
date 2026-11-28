import SalsaLlbc
import ScryptAlternating

namespace Abc.Refine.Scrypt.Source

open Abc.Spec.Scrypt.Functional

abbrev WordState := Fin 16 → BitVec 32

/-- RFC 7914 § 3 quarter round with wrapping 32-bit sums. -/
def quarter (input : WordState) (a b c d : Fin 16) : WordState :=
  let y0 := input a
  let y1 := input b
  let y2 := input c
  let y3 := input d
  let z1 := y1 ^^^ (y0 + y3).rotateLeft 7
  let z2 := y2 ^^^ (z1 + y0).rotateLeft 9
  let z3 := y3 ^^^ (z2 + z1).rotateLeft 13
  let z0 := y0 ^^^ (z3 + z2).rotateLeft 18
  fun j => if j == a then z0 else if j == b then z1 else if j == c then z2
    else if j == d then z3 else input j

/-- The column and row groups of the RFC's reference core. -/
def doubleRound (input : WordState) : WordState :=
  let columns := quarter (quarter (quarter (quarter input 0 4 8 12) 5 9 13 1) 10 14 2 6) 15 3 7 11
  quarter (quarter (quarter (quarter columns 0 1 2 3) 5 6 7 4) 10 11 8 9) 15 12 13 14

def rfcSalsa8 (input : WordState) : WordState :=
  let state := doubleRound (doubleRound (doubleRound (doubleRound input)))
  fun i => input i + state i

private theorem casesWords (predicate : Fin 16 → Prop)
    (h0 : predicate 0) (h1 : predicate 1) (h2 : predicate 2) (h3 : predicate 3)
    (h4 : predicate 4) (h5 : predicate 5) (h6 : predicate 6) (h7 : predicate 7)
    (h8 : predicate 8) (h9 : predicate 9) (h10 : predicate 10) (h11 : predicate 11)
    (h12 : predicate 12) (h13 : predicate 13) (h14 : predicate 14) (h15 : predicate 15)
    (i : Fin 16) : predicate i := by
  have lt := i.isLt
  have indices : i.val = 0 ∨ i.val = 1 ∨ i.val = 2 ∨ i.val = 3 ∨
      i.val = 4 ∨ i.val = 5 ∨ i.val = 6 ∨ i.val = 7 ∨
      i.val = 8 ∨ i.val = 9 ∨ i.val = 10 ∨ i.val = 11 ∨
      i.val = 12 ∨ i.val = 13 ∨ i.val = 14 ∨ i.val = 15 := by omega
  rcases indices with h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h
  all_goals
    first
    | simpa only [show i = (0 : Fin 16) from Fin.ext h] using h0
    | simpa only [show i = (1 : Fin 16) from Fin.ext h] using h1
    | simpa only [show i = (2 : Fin 16) from Fin.ext h] using h2
    | simpa only [show i = (3 : Fin 16) from Fin.ext h] using h3
    | simpa only [show i = (4 : Fin 16) from Fin.ext h] using h4
    | simpa only [show i = (5 : Fin 16) from Fin.ext h] using h5
    | simpa only [show i = (6 : Fin 16) from Fin.ext h] using h6
    | simpa only [show i = (7 : Fin 16) from Fin.ext h] using h7
    | simpa only [show i = (8 : Fin 16) from Fin.ext h] using h8
    | simpa only [show i = (9 : Fin 16) from Fin.ext h] using h9
    | simpa only [show i = (10 : Fin 16) from Fin.ext h] using h10
    | simpa only [show i = (11 : Fin 16) from Fin.ext h] using h11
    | simpa only [show i = (12 : Fin 16) from Fin.ext h] using h12
    | simpa only [show i = (13 : Fin 16) from Fin.ext h] using h13
    | simpa only [show i = (14 : Fin 16) from Fin.ext h] using h14
    | simpa only [show i = (15 : Fin 16) from Fin.ext h] using h15

set_option maxRecDepth 4000 in
set_option maxHeartbeats 1200000 in
theorem sourceDoubleRound_refines (input : WordState) : sourceDoubleRound input = doubleRound input := by
  funext i
  apply (casesWords (fun j => sourceDoubleRound input j = doubleRound input j)) <;> rfl

theorem sourceFeed_refines (input tail : WordState) : sourceFeed input tail = fun i => input i + tail i := by
  funext i
  apply (casesWords (fun j => sourceFeed input tail j = input j + tail j)) <;> rfl

/-- The active Rust function computes every RFC output word for every 512-bit input. -/
theorem sourceSalsa8_refines (input : WordState) : sourceSalsa8 input = rfcSalsa8 input := by
  simp only [sourceSalsa8, sourceFeed_refines, sourceDoubleRound_refines, rfcSalsa8]

def packWords (block : Chunk) : WordState := fun w =>
  let byte (i : Fin 4) := block ⟨4 * w.val + i.val, by omega⟩
  ((byte 3 ++ byte 2) ++ byte 1) ++ byte 0

def unpackWords (state : WordState) : Chunk := fun b =>
  (state ⟨b.val / 4, by omega⟩).extractLsb' (8 * (b.val % 4)) 8

def sourceSalsaBytes (block : Chunk) : Chunk := unpackWords (sourceSalsa8 (packWords block))
def rfcSalsaBytes (block : Chunk) : Chunk := unpackWords (rfcSalsa8 (packWords block))

theorem sourceSalsaBytes_refines (block : Chunk) : sourceSalsaBytes block = rfcSalsaBytes block := by
  unfold sourceSalsaBytes rfcSalsaBytes
  rw [sourceSalsa8_refines]

/-- The alternating-buffer construction with the discharged Salsa20/8 provider contract. -/
theorem alternatingWithSourceSalsa_refines
    (providerPbkdf2 rfcPbkdf2 : Pbkdf2) (password salt scratch : Bytes)
    (r lanes output width exponent : Nat)
    (pbkdf2Contract : ∀ p s n, providerPbkdf2 p s 1 n = rfcPbkdf2 p s 1 n)
    (inWord : exponent + 1 ≤ 64) (inPointer : exponent + 1 ≤ width) :
    deriveWith providerPbkdf2
      (fun lane => (Abc.Spec.Scrypt.Alternating.romix
        (byteOps sourceSalsaBytes r) lane scratch width (exponent + 1)).lane)
      password salt r lanes output =
    deriveWith rfcPbkdf2 (fun lane => rfcRomix (byteOps rfcSalsaBytes r) lane (2 ^ (exponent + 1)))
      password salt r lanes output :=
  Abc.Spec.Scrypt.Alternating.construction_refines_with_swaps providerPbkdf2 rfcPbkdf2
    sourceSalsaBytes rfcSalsaBytes password salt scratch r lanes output width exponent
    pbkdf2Contract sourceSalsaBytes_refines inWord inPointer

#print axioms sourceDoubleRound_refines
#print axioms sourceFeed_refines
#print axioms sourceSalsa8_refines
#print axioms sourceSalsaBytes_refines
#print axioms alternatingWithSourceSalsa_refines

end Abc.Refine.Scrypt.Source
