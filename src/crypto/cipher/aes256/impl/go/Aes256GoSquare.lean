import Init.Data.BitVec

namespace Abc.Spec.Aes256.Go

def byteDouble (x : BitVec 8) : BitVec 8 :=
  (x <<< 1) ^^^ (0x1b &&& (0 - (x >>> 7)))

def byteMultiplyStep : Nat → BitVec 8 → BitVec 8 → BitVec 8 → BitVec 8
  | 0, _, _, sum => sum
  | n + 1, x, y, sum => byteMultiplyStep n (byteDouble x) (y >>> 1)
      (sum ^^^ (x &&& (0 - (y &&& 1))))

def byteMultiply (x y : BitVec 8) : BitVec 8 := byteMultiplyStep 8 x y 0

def byteSquare (x : BitVec 8) : BitVec 8 :=
  (x &&& 1) ^^^ (((x >>> 1) &&& 1) * 0x04) ^^^ (((x >>> 2) &&& 1) * 0x10) ^^^
    (((x >>> 3) &&& 1) * 0x40) ^^^ (((x >>> 4) &&& 1) * 0x1b) ^^^
    (((x >>> 5) &&& 1) * 0x6c) ^^^ (((x >>> 6) &&& 1) * 0xab) ^^^
    (((x >>> 7) &&& 1) * 0x9a)

set_option maxRecDepth 4096 in
set_option maxHeartbeats 3000000 in
theorem byte_square_correct :
    ∀ i : Fin 256, let x := BitVec.ofNat 8 i.val
      byteSquare x = byteMultiply x x := by
  decide

#print axioms byte_square_correct

end Abc.Spec.Aes256.Go
