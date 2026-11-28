import Std

namespace Abc.Foundation

abbrev Byte := BitVec 8

def bytesBigEndian (width value : Nat) : List Byte :=
  (List.range width).map fun index => BitVec.ofNat 8 (value / 256 ^ (width - 1 - index))

def bytesLittleEndian (width value : Nat) : List Byte :=
  (List.range width).map fun index => BitVec.ofNat 8 (value / 256 ^ index)

def decodeBigEndian (bytes : List Byte) : Nat :=
  bytes.foldl (fun acc byte => 256 * acc + byte.toNat) 0

def decodeLittleEndian (bytes : List Byte) : Nat :=
  decodeBigEndian bytes.reverse

end Abc.Foundation
