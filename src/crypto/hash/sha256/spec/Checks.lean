import Sha256Spec
import CompressionRefinement
import StreamingRefinement

open Abc.Spec.Sha256

private def abcBytes : Message := [0x61, 0x62, 0x63]

private def expectedAbc : List Byte := [
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
]

private def expectedEmpty : List Byte := [
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
  0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
]

private def streamedAbc : Option (List Byte) := do
  let stream ← Stream.init.update [0x61]
  let stream ← stream.update []
  let stream ← stream.update [0x62, 0x63]
  stream.finalize

def main : IO Unit := do
  unless digest [] == some expectedEmpty do
    throw (IO.userError "SHA-256 empty-message vector mismatch")
  unless digest abcBytes == some expectedAbc && streamedAbc == some expectedAbc do
    throw (IO.userError "SHA-256 NIST abc vector mismatch")
  for length in [0, 55, 56, 63, 64, 65, 119, 120] do
    let pad := padding (List.replicate length 0)
    unless decide (pad.length ≥ 9) && (length + pad.length) % 64 == 0 do
      throw (IO.userError s!"SHA-256 padding mismatch at {length} bytes")
  unless decide (byteLengthAllowed (2 ^ 61 - 1)) && !decide (byteLengthAllowed (2 ^ 61)) do
    throw (IO.userError "SHA-256 message length bound mismatch")
  IO.println "SHA-256 specification checks passed"

#print axioms Abc.Spec.Sha256.Stream.update_within_domain
#print axioms Abc.Spec.Sha256.Stream.rejects_out_of_domain
#print axioms Abc.Spec.Sha256.Stream.finalize_after_update
#print axioms Abc.Refinement.Sha256.compress32_refines
#print axioms Abc.Refine.Sha256.Streaming.update_refines_stream
#print axioms Abc.Refine.Sha256.Streaming.finalizeTrace_refines_accepted
#print axioms Abc.Refine.Sha256.Streaming.finalizeTrace_refines_concat
