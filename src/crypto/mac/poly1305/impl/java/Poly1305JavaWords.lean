namespace Abc.Spec.Poly1305.Java

def radix : Nat := 2 ^ 26

private def clampPart (key : BitVec 128) (offset right left : Nat) (mask : BitVec 128) : BitVec 128 :=
  ((((key.extractLsb' offset 32).zeroExtend 128 >>> right) &&& mask) <<< left)

def clampLimbs (key : BitVec 128) : BitVec 128 :=
  clampPart key 0 0 0 0x3ffffff ||| clampPart key 24 2 26 0x3ffff03 |||
    clampPart key 48 4 52 0x3ffc0ff ||| clampPart key 72 6 78 0x3f03fff |||
    clampPart key 96 8 104 0x00fffff

private def index (i offset right left : Nat) (mask : BitVec 128) : Option Nat :=
  if i < left ∨ 32 ≤ right + (i - left) ∨ mask.getLsbD (i - left) = false then none
  else some (offset + (right + (i - left)))

private def eval (key : BitVec 128) (source : Option Nat) : Bool :=
  (source.map key.getLsbD).getD false

private theorem clampPart_bit (key : BitVec 128) (i offset right left : Nat)
    (mask : BitVec 128) (hi : i < 128) :
    (clampPart key offset right left mask).getLsbD i = eval key (index i offset right left mask) := by
  simp only [clampPart, index, BitVec.getLsbD_shiftLeft, BitVec.getLsbD_and,
    BitVec.getLsbD_ushiftRight, BitVec.zeroExtend_eq_setWidth, BitVec.getLsbD_setWidth,
    BitVec.getLsbD_extractLsb', hi, decide_true, Bool.true_and]
  by_cases hleft : i < left <;> by_cases hright : right + (i - left) < 32 <;>
    cases hmask : mask.getLsbD (i - left) <;>
    simp_all [eval]
  · have notBefore : ¬ i < left := by omega
    have inWord : ¬ 32 ≤ right + (i - left) := by omega
    have inWidth : right + (i - left) < 128 := by omega
    simp [notBefore, inWord, inWidth]
  · intro _ inWord
    omega

private def indices (i : Nat) : List (Option Nat) :=
  [index i 0 0 0 0x3ffffff, index i 24 2 26 0x3ffff03, index i 48 4 52 0x3ffc0ff,
    index i 72 6 78 0x3f03fff, index i 96 8 104 0x00fffff]

private def rfcMask : BitVec 128 := 0x0ffffffc0ffffffc0ffffffc0fffffff

set_option maxRecDepth 4096 in
private theorem index_matches :
    ∀ i : Fin 128, (indices i.val).filterMap id = if rfcMask.getLsbD i.val then [i.val] else [] := by
  decide

private theorem eval_filter (key : BitVec 128) (sources : List (Option Nat)) :
    (sources.filterMap id).any key.getLsbD = sources.any (eval key) := by
  induction sources with
  | nil => rfl
  | cons source tail ih => cases source <;> simp [eval, ih]

theorem clamp_matches_rfc (key : BitVec 128) :
    clampLimbs key = key &&& 0x0ffffffc0ffffffc0ffffffc0fffffff := by
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  have accepts := index_matches ⟨i, hi⟩
  have matched := eval_filter key (indices i)
  change (indices i).filterMap id = (if rfcMask.getLsbD i then [i] else []) at accepts
  rw [accepts] at matched
  simp only [clampLimbs, BitVec.getLsbD_or, BitVec.getLsbD_and, clampPart_bit, hi]
  change _ = (key.getLsbD i && rfcMask.getLsbD i)
  cases keep : rfcMask.getLsbD i <;>
    simpa [keep, indices, Bool.or_assoc] using matched.symm

theorem folded_product_bound (h r : Nat) (hl : h < 3 * radix) (rl : r < radix) :
    h * r ≤ (3 * radix) * (5 * radix) ∧ h * (5 * r) ≤ (3 * radix) * (5 * radix) := by
  have w := Nat.mul_le_mul (Nat.le_of_lt hl) (Nat.mul_le_mul_left 5 (Nat.le_of_lt rl))
  exact ⟨Nat.le_trans (Nat.mul_le_mul_left h (by omega)) w, w⟩

theorem column_bound (a b c d e : Nat)
    (ha : a ≤ (3 * radix) * (5 * radix)) (hb : b ≤ (3 * radix) * (5 * radix))
    (hc : c ≤ (3 * radix) * (5 * radix)) (hd : d ≤ (3 * radix) * (5 * radix))
    (he : e ≤ (3 * radix) * (5 * radix)) : a + b + c + d + e < 2 ^ 59 := by
  unfold radix at *
  omega

def sweep (a b c d e : Nat) : Nat × Nat × Nat × Nat :=
  let b := b + a / radix
  let c := c + b / radix
  let d := d + c / radix
  let e := e + d / radix
  (b, c, d, e)

theorem carry_intermediates_signed (a b c d e : Nat)
    (ha : a < 2 ^ 59) (hb : b < 2 ^ 59) (hc : c < 2 ^ 59)
    (hd : d < 2 ^ 59) (he : e < 2 ^ 59) :
    let (b', c', d', e') := sweep a b c d e
    let low := a % radix + 5 * (e' / radix)
    b' < 2 ^ 63 ∧ c' < 2 ^ 63 ∧ d' < 2 ^ 63 ∧ e' < 2 ^ 63 ∧ low < 2 ^ 63 ∧
      b' % radix + low / radix < radix + 1024 := by
  simp only [sweep, radix]
  omega

def select (old candidate overflow : BitVec 64) : BitVec 64 :=
  let mask := 0 - overflow
  (old &&& ~~~mask) ||| ((candidate &&& 0x3ffffff) &&& mask)

theorem reduction_mask (old candidate : BitVec 64) :
    select old candidate 0 = old ∧ select old candidate 1 = candidate &&& 0x3ffffff := by
  constructor
  · change (old &&& ~~~(0#64)) ||| ((candidate &&& 0x3ffffff) &&& 0#64) = old
    simp only [BitVec.not_zero, BitVec.and_allOnes, BitVec.and_zero, BitVec.or_zero]
  · change (old &&& ~~~(BitVec.allOnes 64)) ||| ((candidate &&& 0x3ffffff) &&& BitVec.allOnes 64) = _
    simp only [BitVec.not_allOnes, BitVec.and_zero, BitVec.and_allOnes, BitVec.zero_or]

theorem tag_word_bound (word pad carry : Nat)
    (hw : word < 2 ^ 32) (hp : pad < 2 ^ 32) (hc : carry ≤ 1) :
    word + pad + carry < 2 ^ 33 ∧ (word + pad + carry) / 2 ^ 32 ≤ 1 := by
  omega

#print axioms clamp_matches_rfc
#print axioms folded_product_bound
#print axioms column_bound
#print axioms carry_intermediates_signed
#print axioms reduction_mask
#print axioms tag_word_bound

end Abc.Spec.Poly1305.Java
