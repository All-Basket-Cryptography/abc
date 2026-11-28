import Abc.Foundation.Encoding

namespace Abc.Spec.Sha3Encoding

abbrev Byte := Abc.Foundation.Byte
abbrev Lane := BitVec 64

def rateBytes : Nat := 136

-- FIPS 202 uses little-endian bytes within a Keccak-p[1600] lane.
def encodeLane (lane : Lane) : List Byte :=
  Abc.Foundation.bytesLittleEndian 8 lane.toNat

def decodeLane (bytes : List Byte) : Lane :=
  BitVec.ofNat 64 (Abc.Foundation.decodeLittleEndian bytes)

-- The byte-aligned SHA-3 domain separator and pad10*1 occupy the same
-- byte at the upper rate boundary. An exact-rate message has an empty tail.
def paddedTail (tail : List Byte) : Option (List Byte) :=
  if tail.length >= rateBytes then none
  else if tail.length + 1 = rateBytes then some (tail ++ [0x86])
  else some (tail ++ [0x06] ++ List.replicate (rateBytes - tail.length - 2) 0 ++ [0x80])

theorem encodeLane_example : encodeLane 0x0706050403020100 = [0, 1, 2, 3, 4, 5, 6, 7] := by
  decide

theorem decodeLane_example : decodeLane [0, 1, 2, 3, 4, 5, 6, 7] = 0x0706050403020100 := by
  decide

theorem paddedTail_rateBoundary : paddedTail (List.replicate 135 0) = some (List.replicate 135 0 ++ [0x86]) := by
  simp [paddedTail, rateBytes]

end Abc.Spec.Sha3Encoding
