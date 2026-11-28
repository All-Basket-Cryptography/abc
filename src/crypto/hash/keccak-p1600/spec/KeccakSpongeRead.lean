import KeccakRound
import KeccakReader

namespace Abc.Spec.Keccak.SpongeRead

open Abc.Spec.KeccakRound
open Abc.Spec.Keccak.Reader (Cursor read readTrace read_correct read_trace_correct)

def wordByte (blocks : List Block) (position : Nat) : Byte :=
  (blocks[position / 136]?.getD (fun _ => 0)) (Fin.ofNat 136 position)

def specBit (blocks : List BitBlock) (position : Nat) (bit : Fin 8) : Bool :=
  (blocks[position / 136]?.getD (fun _ _ => false)) (Fin.ofNat 136 position) bit

theorem word_byte_bits (blocks : List Block) (position : Nat) (bit : Fin 8) :
    (wordByte blocks position).getLsbD bit.val = specBit (blocks.map blockBits) position bit := by
  unfold wordByte specBit
  rw [List.getElem?_map]
  cases blocks[position / 136]? <;> simp [blockBits]

/-- The FIPS bit sponge supplies the byte reader with enough complete output
blocks for the requested interval. -/
theorem read_bits_match_fips (domain : Domain) (used : Nat) (within : used < 136)
    (absorbed : List Block) (tail : Block) (initial : State) (cursor : Cursor)
    (requested : Nat) (bit : Fin 8) :
    let count := (cursor.offset + requested + 135) / 136
    let words := wordOutput count
      (wordAbsorb (absorbed.foldl wordAbsorb initial) (paddingWrites domain used tail))
    let bits := bitOutput count
      (bitAbsorb (absorbed.foldl bitAbsorb (bitsOf initial)) (paddedRate domain used tail))
    ((read (wordByte words) cursor requested).1.map (fun byte => byte.getLsbD bit.val)) =
      (List.range' cursor.offset requested).map (fun position => specBit bits position bit) := by
  dsimp
  rw [(read_correct _ cursor requested).1, List.map_map]
  apply List.map_congr_left
  intro position _
  rw [Function.comp_apply]
  change (wordByte _ position).getLsbD bit.val = _
  rw [word_byte_bits, sponge_blocks_match domain used within]

theorem requested_blocks_suffice (cursor : Cursor) (requested displacement : Nat) (inside : displacement < requested) :
    (cursor.offset + displacement) / 136 < (cursor.offset + requested + 135) / 136 := by
  omega

/-- Output bits are independent of how an XOF caller partitions its reads. -/
theorem partitioned_bits_match_fips (domain : Domain) (used : Nat) (within : used < 136)
    (absorbed : List Block) (tail : Block) (initial : State) (cursor : Cursor)
    (requests : List Nat) (bit : Fin 8) :
    let count := (cursor.offset + requests.sum + 135) / 136
    let words := wordOutput count
      (wordAbsorb (absorbed.foldl wordAbsorb initial) (paddingWrites domain used tail))
    let bits := bitOutput count
      (bitAbsorb (absorbed.foldl bitAbsorb (bitsOf initial)) (paddedRate domain used tail))
    ((readTrace (wordByte words) cursor requests).1.map (fun byte => byte.getLsbD bit.val)) =
      (List.range' cursor.offset requests.sum).map (fun position => specBit bits position bit) := by
  dsimp
  rw [(read_trace_correct _ cursor requests).1]
  exact read_bits_match_fips domain used within absorbed tail initial cursor requests.sum bit

#print axioms word_byte_bits
#print axioms read_bits_match_fips
#print axioms requested_blocks_suffice
#print axioms partitioned_bits_match_fips

end Abc.Spec.Keccak.SpongeRead
