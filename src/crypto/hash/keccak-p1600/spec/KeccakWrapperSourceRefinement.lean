import KeccakWrapperLlbc

namespace Abc.Refine.Keccak.WrapperSource

open Abc.Spec.KeccakRound
open Abc.Refine.Keccak.Source

private def digestIndex (byte : Fin 32) : Fin 136 :=
  ⟨byte.val, Nat.lt_trans byte.isLt (by decide)⟩

theorem sourceSha3Padding_refines (used : Nat) (tail : Block) :
    sourceSha3Padding used tail = paddingWrites .sha3 used tail := by
  rfl

theorem sourceShakePadding_refines (used : Nat) (tail : Block) :
    sourceShakePadding used tail = paddingWrites .shake used tail := by
  rfl

theorem sourceSha3Wire_refines (state : State) (byte : Fin 32) :
    sourceSha3Wire state byte = wordRate state (digestIndex byte) := by
  rfl

theorem sourceShakeWire_refines (state : State) : sourceShakeWire state = wordRate state := by
  rfl

/-- All 256 returned bits from SHA3-256's digest wrapper refine the FIPS 202 sponge. -/
theorem sourceSha3Digest_bits (blocks : List Block) (used : Nat) (within : used < 136)
    (tail : Block) (byte : Fin 32) (z : Fin 8) :
    (sourceSha3Digest blocks used tail byte).getLsbD z.val =
      bitRate (bitAbsorb (blocks.foldl bitAbsorb (fun _ _ => false)) (paddedRate .sha3 used tail))
        (digestIndex byte) z := by
  rw [sourceSha3Digest, sourceSha3Wire_refines]
  change blockBits (wordRate _) (digestIndex byte) z = _
  rw [output_rate_lifts, sourceAbsorb_bits, sourceAbsorb_blocks_bits,
    sourceSha3Padding_refines, padding_writes_match .sha3 used within]
  have zero : bitsOf (fun _ => 0) = fun _ _ => false := by
    funext lane bit
    simp [bitsOf]
  rw [zero]

/-- SHAKE256 enters the reader with the finalized lanes, a little-endian rate block and offset zero. -/
theorem sourceShakeFinalize_bits (state : State) (used : Nat) (within : used < 136) (tail : Block) :
    let reader := sourceShakeFinalize state used tail
    let expected := bitAbsorb (bitsOf state) (paddedRate .shake used tail)
    bitsOf reader.1 = expected ∧ blockBits reader.2.1 = bitRate expected ∧ reader.2.2 = 0 := by
  have lanes : bitsOf (sourceAbsorb state (sourceShakePadding used tail)) =
      bitAbsorb (bitsOf state) (paddedRate .shake used tail) := by
    rw [sourceAbsorb_bits, sourceShakePadding_refines, padding_writes_match .shake used within]
  refine ⟨lanes, ?_, rfl⟩
  dsimp only [sourceShakeFinalize]
  rw [sourceShakeWire_refines, output_rate_lifts, lanes]

#print axioms sourceSha3Padding_refines
#print axioms sourceShakePadding_refines
#print axioms sourceSha3Wire_refines
#print axioms sourceShakeWire_refines
#print axioms sourceSha3Digest_bits
#print axioms sourceShakeFinalize_bits

end Abc.Refine.Keccak.WrapperSource
