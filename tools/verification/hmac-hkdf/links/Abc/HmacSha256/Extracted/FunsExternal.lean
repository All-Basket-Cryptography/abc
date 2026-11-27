import Abc.HmacSha256.Extracted.Types
import Abc.Sha256.Extracted.Funs

open Aeneas.Std

namespace abc_sha256

abbrev DIGEST_BYTES : Result Usize := .ok Abc.Sha256.Extracted.DIGEST_BYTES
abbrev MAX_MESSAGE_BYTES := Abc.Sha256.Extracted.MAX_MESSAGE_BYTES

abbrev Sha256.new := Abc.Sha256.Extracted.Sha256.new
abbrev Sha256.update := Abc.Sha256.Extracted.Sha256.update
abbrev Sha256.finalize := Abc.Sha256.Extracted.Sha256.finalize
abbrev digest := Abc.Sha256.Extracted.digest

end abc_sha256
