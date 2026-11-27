import HkdfApi

namespace Abc.HkdfSha256.TrustedClaims

open Aeneas Aeneas.Std
open Abc.Spec.Sha256 (Message)
open Abc.HkdfSha256.Extracted (HkdfError Prk)
open Abc.Refine.HkdfSha256.Implementation

private abbrev SpecError := Abc.Spec.HkdfSha256.Error

private def bytes (data : List U8) : Message := data.map U8.bv

private def expectedError : SpecError → HkdfError
  | .saltTooLong => .SaltTooLong
  | .inputTooLong => .InputTooLong
  | .prkTooShort => .PrkTooShort
  | .prkTooLong => .PrkTooLong
  | .infoTooLong => .InfoTooLong
  | .outputTooLong => .OutputTooLong

private def expectedExtract (salt : Option Message) (input : Message) : Except SpecError Message :=
  match Abc.Spec.HmacSha256.authenticate (salt.getD (List.replicate 32 0)) input with
  | .ok key => .ok key
  | .error .keyTooLong => .error .saltTooLong
  | .error .messageTooLong => .error .inputTooLong

private def expectedValidation (key info length : Nat) : Except SpecError Unit :=
  if key < 32 then .error .prkTooShort
  else if 2305843009213693951 < key then .error .prkTooLong
  else if 8160 < length then .error .outputTooLong
  else if length = 0 then .ok ()
  else if 2305843009213693887 - (if 32 < length then 33 else 1) < info then .error .infoTooLong
  else .ok ()

private theorem validation_contract (key info length : Nat) :
    Abc.Spec.HkdfSha256.validateExpansion key info length = expectedValidation key info length := by
  simp [Abc.Spec.HkdfSha256.validateExpansion, Abc.Spec.HkdfSha256.maximumOutput,
    Abc.Spec.HkdfSha256.tagBytes, expectedValidation, Abc.Refine.HkdfSha256.key_above_limit,
    ← Abc.Refine.HkdfSha256.info_above_limit, Abc.Spec.HkdfSha256.infoOverhead]

private def expectedBlock (key info : Message) : Nat → Message
  | 0 => []
  | counter + 1 => Abc.Spec.HmacSha256.tag key
      (expectedBlock key info counter ++ info ++ [BitVec.ofNat 8 (counter + 1)])

private def expectedMaterial (key info : Message) : Nat → Message
  | 0 => []
  | counter + 1 => expectedMaterial key info counter ++ expectedBlock key info (counter + 1)

private theorem block_contract (key info : Message) (counter : Nat) :
    Abc.Spec.HkdfSha256.block key info counter = expectedBlock key info counter := by
  induction counter with
  | zero => rfl
  | succ counter prior => simp only [Abc.Spec.HkdfSha256.block, expectedBlock, prior]

private theorem material_contract (key info : Message) (counter : Nat) :
    Abc.Spec.HkdfSha256.material key info counter = expectedMaterial key info counter := by
  induction counter with
  | zero => rfl
  | succ counter prior =>
    simp only [Abc.Spec.HkdfSha256.material, expectedMaterial, prior, block_contract]

private def expectedExpand (key info : Message) (length : Nat) : Except SpecError Message := do
  expectedValidation key.length info.length length
  return (expectedMaterial key info ((length + 31) / 32)).take length

private theorem expand_contract (key info : Message) (length : Nat) :
    Abc.Spec.HkdfSha256.expand key info length = expectedExpand key info length := by
  have count : Abc.Spec.HkdfSha256.blockCount length = (length + 31) / 32 := by
    simp only [Abc.Spec.HkdfSha256.blockCount, Abc.Spec.HkdfSha256.tagBytes]
    omega
  simp only [Abc.Spec.HkdfSha256.expand, Abc.Spec.HkdfSha256.expandMaterial,
    expectedExpand, validation_contract, material_contract, count]

private def expectedOutput (original : Slice U8)
    (result : core.result.Result Unit HkdfError × Slice U8) (expected : Except SpecError Message) : Prop :=
  match expected with
  | .ok material => result.1 = .Ok () ∧ bytes result.2.val = material
  | .error error => result = (.Err (expectedError error), original)

private theorem output_contract (original : Slice U8)
    (result : core.result.Result Unit HkdfError × Slice U8) (expected : Except SpecError Message) :
    OutputRefines original result expected ↔ expectedOutput original result expected := by
  cases expected <;> rfl

example (salt : Option (Slice U8)) (input : Slice U8) :
    ∃ result, Abc.HkdfSha256.Extracted.extract salt input = .ok result ∧
      match expectedExtract (salt.map (fun key => bytes key.val)) (bytes input.val) with
      | .ok key => ∃ out, result = .Ok out ∧ bytes out.val = key
      | .error reason => result = .Err (expectedError reason) := by
  obtain ⟨result, ran, correct⟩ := WP.spec_imp_exists (extract_refines salt input)
  exact ⟨result, ran, correct⟩

example (key info output : Slice U8) :
    ∃ result, Abc.HkdfSha256.Extracted.expand key info output = .ok result ∧
      expectedOutput output result (expectedExpand (bytes key.val) (bytes info.val) output.val.length) := by
  obtain ⟨result, ran, correct⟩ := WP.spec_imp_exists (expand_refines key info output)
  rw [expand_contract] at correct
  exact ⟨result, ran, (output_contract _ _ _).mp correct⟩

example (key : Prk) : Prk.as_bytes key = .ok key := prk_as_bytes_refines key

example (key : Prk) (info output : Slice U8) :
    ∃ result, Prk.expand key info output = .ok result ∧
      expectedOutput output result (expectedExpand (bytes key.val) (bytes info.val) output.val.length) := by
  obtain ⟨result, ran, correct⟩ := WP.spec_imp_exists (prk_expand_refines key info output)
  rw [expand_contract] at correct
  exact ⟨result, ran, (output_contract _ _ _).mp correct⟩

example (salt : Option (Slice U8)) (input info output : Slice U8) :
    ∃ result, Abc.HkdfSha256.Extracted.derive salt input info output = .ok result ∧
      expectedOutput output result (do
        let key ← expectedExtract (salt.map (fun value => bytes value.val)) (bytes input.val)
        expectedExpand key (bytes info.val) output.val.length) := by
  obtain ⟨result, ran, correct⟩ := WP.spec_imp_exists (derive_refines salt input info output)
  unfold Abc.Spec.HkdfSha256.derive at correct
  simp only [expand_contract] at correct
  exact ⟨result, ran, (output_contract _ _ _).mp correct⟩

#print axioms Abc.Refine.HkdfSha256.validate_expansion_refines
#print axioms Abc.Refine.HkdfSha256.Implementation.extract_refines
#print axioms Abc.Refine.HkdfSha256.Implementation.expand_refines
#print axioms Abc.Refine.HkdfSha256.Implementation.prk_as_bytes_refines
#print axioms Abc.Refine.HkdfSha256.Implementation.prk_expand_refines
#print axioms Abc.Refine.HkdfSha256.Implementation.derive_refines

end Abc.HkdfSha256.TrustedClaims
