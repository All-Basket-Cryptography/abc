import Init.Data.Nat.Bitwise.Lemmas

namespace Abc.Spec.ProviderInputs.MlKem768

def modulus : Nat := 3329

structure ByteTriple where
  low : Fin 256
  middle : Fin 256
  high : Fin 256
  deriving DecidableEq

structure CoefficientPair where
  first : Fin 4096
  second : Fin 4096
  deriving DecidableEq

-- ByteDecode_12 on a single triple, before any additional modulus check.
def unpack (wire : ByteTriple) : CoefficientPair :=
  ⟨⟨wire.low.val + 256 * (wire.middle.val % 16), by
       have lo := wire.low.isLt
       omega⟩,
   ⟨wire.middle.val / 16 + 16 * wire.high.val, by
       have mid := wire.middle.isLt
       have hi := wire.high.isLt
       omega⟩⟩

def pack (coefficients : CoefficientPair) : ByteTriple :=
  ⟨⟨coefficients.first.val % 256, by omega⟩,
   ⟨coefficients.first.val / 256 + 16 * (coefficients.second.val % 16), by
       have first := coefficients.first.isLt
       omega⟩,
   ⟨coefficients.second.val / 16, by
       have second := coefficients.second.isLt
       omega⟩⟩

theorem unpack_preserves_little_endian_value (wire : ByteTriple) :
    (unpack wire).first.val + 4096 * (unpack wire).second.val =
      wire.low.val + 256 * wire.middle.val + 65536 * wire.high.val := by
  simp only [unpack]
  omega

theorem unpack_matches_bit_operations (wire : ByteTriple) :
    (unpack wire).first.val = wire.low.val ||| ((wire.middle.val &&& 15) <<< 8) ∧
    (unpack wire).second.val = (wire.middle.val >>> 4) ||| (wire.high.val <<< 4) := by
  constructor
  · have lowFits : wire.low.val < 2 ^ 8 := wire.low.isLt
    have maskEq : wire.middle.val &&& 15 = wire.middle.val % 16 :=
      Nat.and_two_pow_sub_one_eq_mod wire.middle.val 4
    rw [maskEq, Nat.or_comm, ← Nat.shiftLeft_add_eq_or_of_lt lowFits]
    simp only [unpack, Nat.shiftLeft_eq]
    omega
  · have upperFits : wire.middle.val >>> 4 < 2 ^ 4 := by
      rw [Nat.shiftRight_eq_div_pow]
      have width := wire.middle.isLt
      omega
    rw [Nat.or_comm, ← Nat.shiftLeft_add_eq_or_of_lt upperFits]
    simp only [unpack, Nat.shiftLeft_eq, Nat.shiftRight_eq_div_pow]
    omega

theorem unpack_pack (coefficients : CoefficientPair) : unpack (pack coefficients) = coefficients := by
  cases coefficients with
  | mk first second =>
    have firstWidth := first.isLt
    have secondWidth := second.isLt
    simp only [unpack, pack, CoefficientPair.mk.injEq, Fin.ext_iff, Fin.val_mk]
    constructor <;> omega

theorem pack_unpack (wire : ByteTriple) : pack (unpack wire) = wire := by
  cases wire with
  | mk low middle high =>
    have lowWidth := low.isLt
    have middleWidth := middle.isLt
    have highWidth := high.isLt
    simp only [unpack, pack, ByteTriple.mk.injEq, Fin.ext_iff, Fin.val_mk]
    exact ⟨by omega, by omega, by omega⟩

def canonical (wire : ByteTriple) : Prop :=
  (unpack wire).first.val < modulus ∧ (unpack wire).second.val < modulus

def canonicalCheck (wire : ByteTriple) : Bool :=
  (decide ((unpack wire).first.val < modulus)) &&
    (decide ((unpack wire).second.val < modulus))

def reduce (coefficients : CoefficientPair) : CoefficientPair :=
  ⟨⟨coefficients.first.val % modulus, by
       unfold modulus
       omega⟩,
   ⟨coefficients.second.val % modulus, by
       unfold modulus
       omega⟩⟩

theorem canonical_check_iff (wire : ByteTriple) : canonicalCheck wire = true ↔ canonical wire := by
  simp [canonicalCheck, canonical]

theorem reduce_fixed_iff (coefficients : CoefficientPair) :
    reduce coefficients = coefficients ↔
      coefficients.first.val < modulus ∧ coefficients.second.val < modulus := by
  cases coefficients with
  | mk first second =>
    simp only [reduce, CoefficientPair.mk.injEq, Fin.ext_iff, modulus]
    constructor
    · rintro ⟨hFirst, hSecond⟩
      exact ⟨by omega, by omega⟩
    · rintro ⟨hFirst, hSecond⟩
      exact ⟨Nat.mod_eq_of_lt hFirst, Nat.mod_eq_of_lt hSecond⟩

theorem canonical_iff_reencode_after_reduction (wire : ByteTriple) :
    canonicalCheck wire = true ↔ pack (reduce (unpack wire)) = wire := by
  rw [canonical_check_iff, canonical, ← reduce_fixed_iff]
  constructor
  · intro fixed
    rw [fixed, pack_unpack]
  · intro encoded
    simpa only [unpack_pack] using congrArg unpack encoded

-- The key format has 384 triples covering all 768 packed coefficients,
-- followed by 32 bytes of rho. Neither decoding nor the modulus check alters rho.
structure EncapsulationKeyBytes where
  triples : Fin 384 → ByteTriple
  rho : Fin 32 → Fin 256

def normalizeKey (key : EncapsulationKeyBytes) : EncapsulationKeyBytes :=
  ⟨fun i => pack (reduce (unpack (key.triples i))), key.rho⟩

theorem complete_key_acceptance (key : EncapsulationKeyBytes) :
    (∀ i, canonicalCheck (key.triples i) = true) ↔ normalizeKey key = key := by
  constructor
  · intro accepted
    have same : (fun i => pack (reduce (unpack (key.triples i)))) = key.triples := by
      funext i
      exact (canonical_iff_reencode_after_reduction (key.triples i)).mp (accepted i)
    cases key
    unfold normalizeKey
    simp only at same
    rw [same]
  · intro unchanged i
    apply (canonical_iff_reencode_after_reduction (key.triples i)).mpr
    exact congrArg (fun k : EncapsulationKeyBytes => k.triples i) unchanged

theorem triple_offset_bounds (i : Fin 384) : 3 * i.val + 2 < 1152 := by
  have valid := i.isLt
  omega

#print axioms unpack_preserves_little_endian_value
#print axioms unpack_matches_bit_operations
#print axioms unpack_pack
#print axioms pack_unpack
#print axioms canonical_check_iff
#print axioms reduce_fixed_iff
#print axioms canonical_iff_reencode_after_reduction
#print axioms complete_key_acceptance
#print axioms triple_offset_bounds

end Abc.Spec.ProviderInputs.MlKem768
