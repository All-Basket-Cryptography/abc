import Poly1305ByteRefinement
import Poly1305SourceRefinement

namespace Abc.Refine.Poly1305.Final

open Aeneas Aeneas.Std Result
open Abc.Poly1305.Extracted
open Abc.Refine.Poly1305 (columns source_final_carry_refines source_reduce_final_refines source_pack_low128_refines)
open Abc.Refine.Poly1305.Bytes (blockValue fromLEBytes_toNat)
open Abc.Spec.Poly1305.Go (live value modulus)

private abbrev Words := Aeneas.Std.Array U64 5#usize

/-- The actual Rust pad addition wraps at 128 bits and serializes all 16 bytes
in little-endian order. -/
theorem source_add_pad_and_serialize_refines (low pad : U128) :
    add_pad_and_serialize low pad ⦃ out =>
      out.val.map U8.bv = (BitVec.ofNat 128 (low.val + pad.val)).toLEBytes ⦄ := by
  simp only [add_pad_and_serialize, lift, Aeneas.Std.bind_tc_ok, WP.spec_ok,
    core.num.U128.to_le_bytes, Aeneas.Std.Array.from_val, List.map_map]
  have exactSum : (core.num.U128.wrapping_add low pad).bv = BitVec.ofNat 128 (low.val + pad.val) := by
    apply BitVec.eq_of_toNat_eq
    change (core.num.U128.wrapping_add low pad).val = _
    rw [core.num.U128.wrapping_add_val_eq, BitVec.toNat_ofNat, UScalar.size, UScalarTy.U128_numBits_eq]
  rw [exactSum]
  exact List.map_id' _

/-- This is the exact active tag computation after absorption. It includes
carry normalization, canonical field reduction, packing, pad and all bytes. -/
theorem source_finish_tag_refines (h : Words) (pad : U128) (invariant : live (columns h)) :
    finish_tag h pad ⦃ out =>
      out.val.map U8.bv = (BitVec.ofNat 128 (value (columns h) % modulus + pad.val)).toLEBytes ⦄ := by
  unfold finish_tag
  step with (source_final_carry_refines h invariant) as ⟨normalized, bound, residue⟩
  step with (source_reduce_final_refines normalized bound) as ⟨reduced, reducedBound, canonical⟩
  step with (source_pack_low128_refines reduced reducedBound) as ⟨packed, packedValue⟩
  step with (source_add_pad_and_serialize_refines packed pad) as ⟨out, serialized⟩
  rw [serialized]
  apply congrArg BitVec.toLEBytes
  apply BitVec.eq_of_toNat_eq
  simp only [BitVec.toNat_ofNat, packedValue, canonical, residue, Nat.mod_add_mod]

/-- Decoding the 16 returned bytes yields the RFC integer tag. -/
theorem source_finish_tag_value (h : Words) (pad : U128) (invariant : live (columns h)) :
    finish_tag h pad ⦃ out => blockValue out = (value (columns h) % modulus + pad.val) % 2^128 ⦄ := by
  refine WP.spec_mono (source_finish_tag_refines h pad invariant) ?_
  intro out bytes
  rw [blockValue, bytes, ← fromLEBytes_toNat, BitVec.fromLEBytes_toLEBytes (by decide),
    BitVec.toNat_cast, BitVec.toNat_ofNat]

#print axioms source_add_pad_and_serialize_refines
#print axioms source_finish_tag_refines
#print axioms source_finish_tag_value

end Abc.Refine.Poly1305.Final
