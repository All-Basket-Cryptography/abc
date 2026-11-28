import Poly1305Radix13

namespace Abc.Spec.Poly1305.Radix13.Window

abbrev Limbs := Fin 10 → Nat

/-- Cache nine folded key limbs, followed by all ten ordinary key limbs. -/
def cachedKey (key : Limbs) (index : Fin 19) : Nat :=
  if folded : index.val < 9 then 5 * key ⟨index.val + 1, by omega⟩
  else key ⟨index.val - 9, by have bound := index.isLt; omega⟩

def windowIndex (column input : Fin 10) : Fin 19 :=
  ⟨9 + column.val - input.val, by have bound := column.isLt; omega⟩

/-- A cyclic convolution column uses factor five precisely when the degree
wraps through ten in radix 2^13. -/
def coefficient (key : Limbs) (column input : Fin 10) : Nat :=
  (if input.val ≤ column.val then 1 else 5) *
    key ⟨(10 + column.val - input.val) % 10, Nat.mod_lt _ (by decide)⟩

theorem window_entry_refines (key : Limbs) (column input : Fin 10) :
    cachedKey key (windowIndex column input) = coefficient key column input := by
  have source := input.isLt
  have target := column.isLt
  by_cases order : input.val ≤ column.val
  · have high : ¬ 9 + column.val - input.val < 9 := by omega
    have lane : (10 + column.val - input.val) % 10 = 9 + column.val - input.val - 9 := by omega
    simp [cachedKey, windowIndex, coefficient, high, order, lane]
  · have low : 9 + column.val - input.val < 9 := by omega
    have lane : (10 + column.val - input.val) % 10 = 9 + column.val - input.val + 1 := by omega
    simp [cachedKey, windowIndex, coefficient, low, order, lane]

def cachedColumn (message key : Limbs) (column : Fin 10) : Nat :=
  (List.ofFn (fun input => message input * cachedKey key (windowIndex column input))).sum

def foldedColumn (message key : Limbs) (column : Fin 10) : Nat :=
  (List.ofFn (fun input => message input * coefficient key column input)).sum

theorem window_column_refines (message key : Limbs) (column : Fin 10) :
    cachedColumn message key column = foldedColumn message key column := by
  simp only [cachedColumn, foldedColumn, window_entry_refines]

private theorem sum_bound (items : List Nat) (bound : Nat) (bounded : ∀ item ∈ items, item ≤ bound) :
    items.sum ≤ items.length * bound := by
  induction items with
  | nil => simp
  | cons first rest ih =>
    have head := bounded first (by simp)
    have tail := ih (fun item member => bounded item (List.mem_cons_of_mem _ member))
    simp only [List.sum_cons, List.length_cons, Nat.succ_mul]
    omega

theorem cache_entry_below_16_bits (key : Limbs) (keyFits : ∀ i, key i < base) (index : Fin 19) :
    cachedKey key index < 2^16 := by
  unfold cachedKey
  split <;> rename_i position
  · have bound := keyFits ⟨index.val + 1, by omega⟩
    simp only [base] at bound
    omega
  · have bound := keyFits ⟨index.val - 9, by have valid := index.isLt; omega⟩
    simp only [base] at bound
    omega

/-- The proof covers every intermediate sum, including the complete column. -/
theorem window_prefix_below_33_bits (message key : Limbs) (column : Fin 10) (count : Nat)
    (messageFits : ∀ i, message i < 2 * base) (keyFits : ∀ i, key i < base) :
    ((List.ofFn (fun input => message input * cachedKey key (windowIndex column input))).take count).sum < 2^33 := by
  let bound := 5 * (2 * base) * base
  let terms := List.ofFn (fun input => message input * cachedKey key (windowIndex column input))
  have termFits (input : Fin 10) : message input * cachedKey key (windowIndex column input) ≤ bound := by
    rw [window_entry_refines]
    unfold coefficient
    let lane : Fin 10 := ⟨(10 + column.val - input.val) % 10, Nat.mod_lt _ (by decide)⟩
    change message input * ((if input.val ≤ column.val then 1 else 5) * key lane) ≤ bound
    have factor : (if input.val ≤ column.val then 1 else 5) ≤ 5 := by split <;> decide
    calc
      _ ≤ message input * (5 * key lane) := Nat.mul_le_mul_left _ (Nat.mul_le_mul_right _ factor)
      _ = 5 * message input * key lane := by ac_rfl
      _ ≤ bound := folded_term_bound _ _ (messageFits input) (keyFits lane)
  have each (item : Nat) (member : item ∈ terms.take count) : item ≤ bound := by
    have inTerms := List.mem_of_mem_take member
    obtain ⟨input, rfl⟩ := List.mem_ofFn.mp inTerms
    exact termFits input
  have length : (terms.take count).length ≤ 10 := by
    simp [terms]
    omega
  calc
    _ ≤ (terms.take count).length * bound := sum_bound _ _ each
    _ ≤ 10 * bound := Nat.mul_le_mul_right _ length
    _ < 2^33 := ten_terms_below_33_bits

theorem block_byte_in_range (size offset length : Nat) (byte : Fin size) (valid : offset + size ≤ length) :
    offset + byte.val < length := by
  have bound := byte.isLt
  omega

theorem empty_tag_is_pad (pad : Nat) (fits : pad < 2^128) : (0 + pad) % 2^128 = pad := by
  simpa only [Nat.zero_add] using Nat.mod_eq_of_lt fits

#print axioms window_entry_refines
#print axioms window_column_refines
#print axioms cache_entry_below_16_bits
#print axioms window_prefix_below_33_bits
#print axioms block_byte_in_range
#print axioms empty_tag_is_pad

end Abc.Spec.Poly1305.Radix13.Window
