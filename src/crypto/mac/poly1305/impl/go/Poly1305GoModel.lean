import Std.Tactic.BVDecide

namespace Abc.Spec.Poly1305.Go

def base : Nat := 2^26
def modulus : Nat := base^5 - 5

structure Columns where
  c0 : Nat
  c1 : Nat
  c2 : Nat
  c3 : Nat
  c4 : Nat

def value (d : Columns) : Nat :=
  d.c0 + base * d.c1 + base^2 * d.c2 + base^3 * d.c3 + base^4 * d.c4

def sweep (d : Columns) : Columns :=
  let c1 := d.c1 + d.c0 / base
  let c2 := d.c2 + c1 / base
  let c3 := d.c3 + c2 / base
  let c4 := d.c4 + c3 / base
  ⟨d.c0 % base, c1, c2, c3, c4⟩

def carry (d : Columns) : Columns :=
  let swept := sweep d
  let low := swept.c0 + 5 * (swept.c4 / base)
  ⟨low % base, swept.c1 % base + low / base, swept.c2 % base,
    swept.c3 % base, swept.c4 % base⟩

def bounded (d : Columns) (limit : Nat) : Prop :=
  d.c0 < limit ∧ d.c1 < limit ∧ d.c2 < limit ∧ d.c3 < limit ∧ d.c4 < limit

def live (d : Columns) : Prop :=
  d.c0 < base ∧ d.c1 < base + 1024 ∧ d.c2 < base ∧ d.c3 < base ∧ d.c4 < base

theorem carry_value (d : Columns) :
    value d = value (carry d) + ((sweep d).c4 / base) * modulus := by
  simp only [value, carry, sweep, base, modulus]
  omega

theorem carry_congruence (d : Columns) : value (carry d) % modulus = value d % modulus := by
  rw [carry_value d, Nat.add_mod, Nat.mul_mod, Nat.mod_self, Nat.mul_zero, Nat.zero_mod, Nat.add_zero,
    Nat.mod_mod]

theorem products_fit (h r : Nat) (hh : h < 3 * base) (hr : r < base) :
    h * (5 * r) ≤ (3 * base) * (5 * base) := by
  exact Nat.mul_le_mul (Nat.le_of_lt hh) (Nat.mul_le_mul_left 5 (Nat.le_of_lt hr))

theorem column_fits (a b c d e : Nat)
    (ha : a ≤ (3 * base) * (5 * base)) (hb : b ≤ (3 * base) * (5 * base))
    (hc : c ≤ (3 * base) * (5 * base)) (hd : d ≤ (3 * base) * (5 * base))
    (he : e ≤ (3 * base) * (5 * base)) :
    a + b + c + d + e < 2^59 := by
  unfold base at *
  omega

def productColumns (h r : Columns) : Columns :=
  ⟨h.c0*r.c0 + h.c1*(5*r.c4) + h.c2*(5*r.c3) + h.c3*(5*r.c2) + h.c4*(5*r.c1),
   h.c0*r.c1 + h.c1*r.c0 + h.c2*(5*r.c4) + h.c3*(5*r.c3) + h.c4*(5*r.c2),
   h.c0*r.c2 + h.c1*r.c1 + h.c2*r.c0 + h.c3*(5*r.c4) + h.c4*(5*r.c3),
   h.c0*r.c3 + h.c1*r.c2 + h.c2*r.c1 + h.c3*r.c0 + h.c4*(5*r.c4),
   h.c0*r.c4 + h.c1*r.c3 + h.c2*r.c2 + h.c3*r.c1 + h.c4*r.c0⟩

def highProduct (h r : Columns) : Columns :=
  ⟨h.c1*r.c4 + h.c2*r.c3 + h.c3*r.c2 + h.c4*r.c1,
   h.c2*r.c4 + h.c3*r.c3 + h.c4*r.c2,
   h.c3*r.c4 + h.c4*r.c3,
   h.c4*r.c4,
   0⟩

theorem product_value (h r : Columns) :
    value h * value r = value (productColumns h r) + value (highProduct h r) * modulus := by
  simp only [value, productColumns, highProduct, modulus, base]
  grind

theorem products_reduce (h r : Columns) :
    value (productColumns h r) % modulus = (value h * value r) % modulus := by
  rw [product_value, Nat.add_mod, Nat.mul_mod, Nat.mod_self, Nat.mul_zero, Nat.zero_mod,
    Nat.add_zero, Nat.mod_mod]

theorem product_columns_fit (h r : Columns) (hh : bounded h (3 * base)) (hr : bounded r base) :
    bounded (productColumns h r) (2^59) := by
  have weighted (a b : Nat) (ha : a < 3 * base) (hb : b < base) :=
    products_fit a b ha hb
  have regular (a b : Nat) (ha : a < 3 * base) (hb : b < base) :
      a * b ≤ (3 * base) * (5 * base) :=
    Nat.le_trans (Nat.mul_le_mul_left a (by omega)) (products_fit a b ha hb)
  obtain ⟨h0,h1,h2,h3,h4⟩ := hh
  obtain ⟨r0,r1,r2,r3,r4⟩ := hr
  refine ⟨column_fits _ _ _ _ _ (regular _ _ h0 r0) (weighted _ _ h1 r4) (weighted _ _ h2 r3)
      (weighted _ _ h3 r2) (weighted _ _ h4 r1),
    column_fits _ _ _ _ _ (regular _ _ h0 r1) (regular _ _ h1 r0) (weighted _ _ h2 r4)
      (weighted _ _ h3 r3) (weighted _ _ h4 r2),
    column_fits _ _ _ _ _ (regular _ _ h0 r2) (regular _ _ h1 r1) (regular _ _ h2 r0)
      (weighted _ _ h3 r4) (weighted _ _ h4 r3),
    column_fits _ _ _ _ _ (regular _ _ h0 r3) (regular _ _ h1 r2) (regular _ _ h2 r1)
      (regular _ _ h3 r0) (weighted _ _ h4 r4),
    column_fits _ _ _ _ _ (regular _ _ h0 r4) (regular _ _ h1 r3) (regular _ _ h2 r2)
      (regular _ _ h3 r1) (regular _ _ h4 r0)⟩

theorem sweep_intermediates_fit (d : Columns) (h : bounded d (2^59)) :
    bounded (sweep d) (2^60) := by
  simp only [bounded, sweep, base] at *
  omega

theorem carry_keeps_live (d : Columns) (h : bounded d (2^59)) : live (carry d) := by
  simp only [bounded, live, carry, sweep, base] at *
  omega

def addColumns (h m : Columns) : Columns :=
  ⟨h.c0 + m.c0, h.c1 + m.c1, h.c2 + m.c2, h.c3 + m.c3, h.c4 + m.c4⟩

theorem added_block_fits (h m : Columns) (state : live h) (message : bounded m base) :
    bounded (addColumns h m) (3 * base) := by
  simp only [addColumns, bounded, live, base] at *
  omega

theorem added_block_value (h m : Columns) : value (addColumns h m) = value h + value m := by
  simp only [addColumns, value, base, Nat.mul_add]
  omega

def absorb (r h m : Columns) : Columns := carry (productColumns (addColumns h m) r)

def polynomialStep (r h : Nat) (m : Columns) : Nat := ((h + value m) * r) % modulus

theorem absorb_fits (r h m : Columns) (key : bounded r base) (state : live h) (message : bounded m base) :
    live (absorb r h m) :=
  carry_keeps_live _ (product_columns_fit _ _ (added_block_fits h m state message) key)

theorem state_mod_at_step (x y r : Nat) :
    (((x % modulus) + y) * r) % modulus = ((x + y) * r) % modulus := by
  calc
    _ = (((x % modulus + y) % modulus) * (r % modulus)) % modulus := Nat.mul_mod _ _ _
    _ = (((x + y) % modulus) * (r % modulus)) % modulus := by
      rw [Nat.add_mod (x % modulus), Nat.mod_mod, ← Nat.add_mod x y]
    _ = _ := (Nat.mul_mod _ _ _).symm

theorem absorb_value (r h m : Columns) :
    value (absorb r h m) % modulus = polynomialStep (value r) (value h % modulus) m := by
  unfold absorb polynomialStep
  rw [carry_congruence, products_reduce, added_block_value, state_mod_at_step]

theorem fold_value (r h : Columns) (messages : List Columns) :
    value (messages.foldl (absorb r) h) % modulus =
      messages.foldl (polynomialStep (value r)) (value h % modulus) := by
  induction messages generalizing h with
  | nil => rfl
  | cons m tail ih =>
    simp only [List.foldl_cons, ih, absorb_value]

theorem fold_fits (r h : Columns) (messages : List Columns) (key : bounded r base) (state : live h)
    (input : ∀ m ∈ messages, bounded m base) : live (messages.foldl (absorb r) h) := by
  induction messages generalizing h with
  | nil => exact state
  | cons m tail ih =>
    simp only [List.foldl_cons]
    exact ih _ (absorb_fits r h m key state (input m (by simp))) (fun n hn => input n (by simp [hn]))

theorem carry_normalizes (d : Columns) (h : live d) : bounded (carry d) base := by
  by_cases hc : d.c1 < base <;>
    simp only [bounded, live, carry, sweep, base] at * <;> omega

theorem normalized_value_bounded (d : Columns) (h : bounded d base) : value d < base^5 := by
  simp only [bounded, value, base] at *
  omega

def subtractIfNeeded (x : Nat) : Nat :=
  if base^5 ≤ x + 5 then x + 5 - base^5 else x

theorem canonical_residue (x : Nat) (h : x < base^5) : subtractIfNeeded x = x % modulus := by
  simp only [subtractIfNeeded, modulus, base] at *
  split <;> omega

def maskSelect (old reduced overflow : BitVec 64) : BitVec 64 :=
  let mask := 0 - overflow
  (old &&& ~~~mask) ||| (reduced &&& mask)

theorem mask_select_zero (old reduced : BitVec 64) : maskSelect old reduced 0 = old := by
  unfold maskSelect
  bv_decide

theorem mask_select_one (old reduced : BitVec 64) : maskSelect old reduced 1 = reduced := by
  unfold maskSelect
  bv_decide

#print axioms carry_congruence
#print axioms products_fit
#print axioms column_fits
#print axioms products_reduce
#print axioms product_columns_fit
#print axioms sweep_intermediates_fit
#print axioms carry_keeps_live
#print axioms added_block_fits
#print axioms fold_fits
#print axioms fold_value
#print axioms carry_normalizes
#print axioms normalized_value_bounded
#print axioms canonical_residue
#print axioms mask_select_zero
#print axioms mask_select_one

end Abc.Spec.Poly1305.Go
