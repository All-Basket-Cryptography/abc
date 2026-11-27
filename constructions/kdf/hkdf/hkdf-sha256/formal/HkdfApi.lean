import HkdfRefinement
import HmacRefinement
import ExpandRefinement

namespace Abc.Refine.HkdfSha256.Implementation

open Aeneas Aeneas.Std
open Abc.HkdfSha256.Extracted
open Abc.Spec.Sha256 (Message)
open Abc.Refine.Sha256.Implementation (bytesView bytesView_length)
open Abc.Spec.HkdfSha256 (validateExpansion validateExpansion_eq_ok_iff expandMaterial)

def saltView (salt : Option (Slice U8)) : Option Message :=
  salt.map (fun bytes => bytesView bytes.val)

def ExtractRefines (result : core.result.Result Prk HkdfError)
    (expected : Except Abc.Spec.HkdfSha256.Error Message) : Prop :=
  match expected with
  | .ok prk => ∃ out, result = .Ok out ∧ bytesView out.val = prk
  | .error reason => result = .Err (rustError reason)

def OutputRefines (original : Slice U8) (result : core.result.Result Unit HkdfError × Slice U8)
    (expected : Except Abc.Spec.HkdfSha256.Error Message) : Prop :=
  match expected with
  | .ok bytes => result.1 = .Ok () ∧ bytesView result.2.val = bytes
  | .error reason => result = (.Err (rustError reason), original)

/-- Extraction applies the verified HMAC to IKM and the effective salt, preserving errors. -/
theorem extract_refines (salt : Option (Slice U8)) (input : Slice U8) :
    Abc.HkdfSha256.Extracted.extract salt input ⦃ result =>
      ExtractRefines result (Abc.Spec.HkdfSha256.extract (saltView salt) (bytesView input.val)) ⦄ := by
  let zero := (Aeneas.Std.Array.repeat 32#usize 0#u8).to_slice
  let key := salt.getD zero
  have saltBytes :
      bytesView key.val = (saltView salt).getD (List.replicate Abc.Spec.HkdfSha256.tagBytes 0) := by
    cases salt <;> simp [key, zero, saltView, bytesView, Aeneas.Std.Array.val_to_slice,
      Abc.Spec.HkdfSha256.tagBytes]
  obtain ⟨tag, ran, correct⟩ := WP.spec_imp_exists
    (Abc.Refine.HmacSha256.Implementation.authenticate_refines key input)
  rw [saltBytes] at correct
  unfold Abc.HkdfSha256.Extracted.extract Abc.Spec.HkdfSha256.extract
  rw [← correct]
  cases salt
  all_goals
    simp only [key, zero, Option.getD_none, Option.getD_some] at ran
    simp only [lift, bind_tc_ok, _root_.abc_hmac_sha256.authenticate, ran]
    cases tag with
    | Ok prk =>
      simp [abc_hmac_sha256.transportResult, Abc.Refine.HmacSha256.Implementation.viewResult,
        WP.spec_ok, ExtractRefines]
    | Err reason =>
      cases reason <;> simp [abc_hmac_sha256.transportResult, abc_hmac_sha256.transportError,
        Abc.Refine.HmacSha256.Implementation.viewResult, WP.spec_ok, ExtractRefines, rustError]

/-- The caller's full output slice is unchanged on every validation error. -/
theorem expand_refines (prk info output : Slice U8) :
    Abc.HkdfSha256.Extracted.expand prk info output ⦃ result =>
      OutputRefines output result
        (Abc.Spec.HkdfSha256.expand (bytesView prk.val) (bytesView info.val) output.val.length) ⦄ := by
  unfold Abc.HkdfSha256.Extracted.expand
  simp only [validate_expansion_refines, Slice.len_val, bind_tc_ok]
  cases checked : validateExpansion prk.val.length info.val.length output.val.length with
  | ok value =>
    cases value
    have valid := (validateExpansion_eq_ok_iff _ _ _).mp checked
    simpa [checked, validationResult, core.result.Result.Insts.CoreOpsTry.branch, OutputRefines,
      Abc.Spec.HkdfSha256.expand, bytesView_length] using
      expand_loop_refines prk info output (Aeneas.Std.Array.repeat 32#usize 0#u8) valid
  | error reason =>
    simp [checked, validationResult, core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, OutputRefines, Abc.Spec.HkdfSha256.expand, bytesView_length]

theorem prk_as_bytes_refines (prk : Prk) : Prk.as_bytes prk = .ok prk := rfl

theorem prk_expand_refines (prk : Prk) (info output : Slice U8) :
    Prk.expand prk info output ⦃ result => OutputRefines output result
      (Abc.Spec.HkdfSha256.expand (bytesView prk.val) (bytesView info.val) output.val.length) ⦄ := by
  simpa [Prk.expand, expand_from_prk, lift, Aeneas.Std.Array.val_to_slice] using
    expand_refines prk.to_slice info output

/-- Derive is extraction followed by expansion, with exact output preservation on either error. -/
theorem derive_refines (salt : Option (Slice U8)) (input info output : Slice U8) :
    Abc.HkdfSha256.Extracted.derive salt input info output ⦃ result => OutputRefines output result
      (Abc.Spec.HkdfSha256.derive (saltView salt) (bytesView input.val)
        (bytesView info.val) output.val.length) ⦄ := by
  obtain ⟨result, ran, verified⟩ := WP.spec_imp_exists (extract_refines salt input)
  unfold Abc.HkdfSha256.Extracted.derive Abc.Spec.HkdfSha256.derive
  rw [ran]
  cases extracted : Abc.Spec.HkdfSha256.extract (saltView salt) (bytesView input.val) with
  | ok material =>
    rw [extracted] at verified
    obtain ⟨prk, rfl, prkBytes⟩ := verified
    simp only [bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
    change Prk.expand prk info output ⦃ result => OutputRefines output result
      (Abc.Spec.HkdfSha256.expand material (bytesView info.val) output.val.length) ⦄
    simpa only [prkBytes] using prk_expand_refines prk info output
  | error reason =>
    rw [extracted] at verified
    change result = _ at verified
    rw [verified]
    simp only [bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, WP.spec_ok]
    rfl

end Abc.Refine.HkdfSha256.Implementation
