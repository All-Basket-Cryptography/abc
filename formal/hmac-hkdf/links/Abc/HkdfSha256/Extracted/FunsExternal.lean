import Abc.HkdfSha256.Extracted.Types
import Abc.HmacSha256.Extracted.Funs

open Aeneas Aeneas.Std

namespace abc_hmac_sha256

abbrev TAG_BYTES := Abc.HmacSha256.Extracted.TAG_BYTES
abbrev MAX_KEY_BYTES := Abc.HmacSha256.Extracted.MAX_KEY_BYTES
abbrev MAX_INPUT_BYTES := Abc.HmacSha256.Extracted.MAX_INPUT_BYTES

/-- Charon emits the matched HMAC error enum in each model. Transport its two
    constructors to the corresponding constructors in the consumer. -/
def transportError : Abc.HmacSha256.Extracted.HmacError →
    Abc.HkdfSha256.Extracted.abc_hmac_sha256.HmacError
  | .KeyTooLong => .KeyTooLong
  | .MessageTooLong => .MessageTooLong

def transportResult {α : Type} : core.result.Result α Abc.HmacSha256.Extracted.HmacError →
    core.result.Result α Abc.HkdfSha256.Extracted.abc_hmac_sha256.HmacError
  | .Ok value => .Ok value
  | .Err error => .Err (transportError error)

def HmacSha256.new (key : Slice U8) :
    Result (core.result.Result HmacSha256 Abc.HkdfSha256.Extracted.abc_hmac_sha256.HmacError) := do
  let result ← Abc.HmacSha256.Extracted.HmacSha256.new key
  .ok (transportResult result)

def HmacSha256.update (state : HmacSha256) (input : Slice U8) :
    Result (core.result.Result Unit Abc.HkdfSha256.Extracted.abc_hmac_sha256.HmacError × HmacSha256) := do
  let (result, next) ← Abc.HmacSha256.Extracted.HmacSha256.update state input
  .ok (transportResult result, next)

def HmacSha256.finalize (state : HmacSha256) :
    Result (core.result.Result (Aeneas.Std.Array U8 32#usize)
      Abc.HkdfSha256.Extracted.abc_hmac_sha256.HmacError) := do
  let result ← Abc.HmacSha256.Extracted.HmacSha256.finalize state
  .ok (transportResult result)

def authenticate (key input : Slice U8) :
    Result (core.result.Result (Aeneas.Std.Array U8 32#usize)
      Abc.HkdfSha256.Extracted.abc_hmac_sha256.HmacError) := do
  let result ← Abc.HmacSha256.Extracted.authenticate key input
  .ok (transportResult result)

end abc_hmac_sha256
