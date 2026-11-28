import Aes256Llbc

namespace Abc.Refine.Aes256

open Abc.Extracted

private abbrev Byte := BitVec 8

private def fipsMulX (word : Byte) : Byte :=
  if word.getLsbD 7 then (word <<< 1) ^^^ 0x1b else word <<< 1

private def fipsMul : Nat → Byte → Byte → Byte → Byte
  | 0, _, _, acc => acc
  | fuel + 1, left, right, acc =>
    fipsMul fuel (fipsMulX left) (right >>> 1) (if right.getLsbD 0 then acc ^^^ left else acc)

theorem source_mul_x_refines_fips : ∀ i : Fin 256,
    let word := BitVec.ofNat 8 i.val
    Aes256.mulX word = fipsMulX word := by
  decide +kernel

set_option maxRecDepth 8192 in
set_option maxHeartbeats 3000000 in
theorem source_square_refines_field : ∀ i : Fin 256,
    let word := BitVec.ofNat 8 i.val
    Aes256.square word = fipsMul 8 word word 0 := by
  decide +kernel

theorem source_field_examples : Aes256.mulX 0x80 = 0x1b ∧ Aes256.square 1 = 1 := by
  decide +kernel

private def fipsMixColumn (a b c d : Byte) : Byte × Byte × Byte × Byte :=
  let mul3 word := fipsMulX word ^^^ word
  (fipsMulX a ^^^ mul3 b ^^^ c ^^^ d,
   a ^^^ fipsMulX b ^^^ mul3 c ^^^ d,
   a ^^^ b ^^^ fipsMulX c ^^^ mul3 d,
   mul3 a ^^^ b ^^^ c ^^^ fipsMulX d)

private theorem xor_left_comm (a b c : Byte) : a ^^^ (b ^^^ c) = b ^^^ (a ^^^ c) := by
  rw [← BitVec.xor_assoc, BitVec.xor_comm a b, BitVec.xor_assoc]

private theorem xor_cancel (a b : Byte) : a ^^^ (a ^^^ b) = b := by
  rw [← BitVec.xor_assoc, BitVec.xor_self, BitVec.zero_xor]

private theorem fipsMulX_linear (a b : Byte) : fipsMulX (a ^^^ b) = fipsMulX a ^^^ fipsMulX b := by
  have reduce (left right : Bool) (x y : Byte) :
      (if left ^^ right then (x ^^^ y) ^^^ 0x1b else x ^^^ y) =
        (if left then x ^^^ 0x1b else x) ^^^ (if right then y ^^^ 0x1b else y) := by
    cases left <;> cases right <;>
      simp [BitVec.xor_assoc, BitVec.xor_comm, xor_left_comm]
  unfold fipsMulX
  rw [BitVec.shiftLeft_xor_distrib, BitVec.getLsbD_xor]
  exact reduce (a.getLsbD 7) (b.getLsbD 7) (a <<< 1) (b <<< 1)

theorem source_mix_column_refines_fips (a b c d : Byte) :
    Aes256.mixColumn a b c d = fipsMixColumn a b c d := by
  have mulX (word : Byte) : Aes256.mulX word = fipsMulX word := by
    simpa using source_mul_x_refines_fips word.toFin
  simp [Aes256.mixColumn, fipsMixColumn, mulX, fipsMulX_linear, BitVec.xor_assoc,
    BitVec.xor_comm, xor_left_comm, xor_cancel]

theorem source_mix_column_example : Aes256.mixColumn 1 0 0 0 = (2, 1, 1, 3) := by
  decide +kernel

#print axioms source_mul_x_refines_fips
#print axioms source_square_refines_field
#print axioms source_field_examples
#print axioms source_mix_column_refines_fips
#print axioms source_mix_column_example

end Abc.Refine.Aes256
