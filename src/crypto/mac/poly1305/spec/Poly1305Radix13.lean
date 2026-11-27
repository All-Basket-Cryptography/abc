import Std

namespace Abc.Spec.Poly1305.Radix13

def base : Nat := 2^13

def modulus : Nat := base^10 - 5

structure Columns where
  c0 : Nat
  c1 : Nat
  c2 : Nat
  c3 : Nat
  c4 : Nat
  c5 : Nat
  c6 : Nat
  c7 : Nat
  c8 : Nat
  c9 : Nat

def tailBounded (d : Columns) (bound : Nat) : Prop :=
  d.c1 < bound ∧ d.c2 < bound ∧ d.c3 < bound ∧ d.c4 < bound ∧ d.c5 < bound ∧
    d.c6 < bound ∧ d.c7 < bound ∧ d.c8 < bound ∧ d.c9 < bound

def value (d : Columns) : Nat :=
  d.c0 + base * d.c1 + base^2 * d.c2 + base^3 * d.c3 + base^4 * d.c4 +
    base^5 * d.c5 + base^6 * d.c6 + base^7 * d.c7 + base^8 * d.c8 + base^9 * d.c9

/-- Propagate carry from each column to the next before folding the high word. -/
private def propagated (d : Columns) : Columns :=
  let c1 := d.c1 + d.c0 / base
  let c2 := d.c2 + c1 / base
  let c3 := d.c3 + c2 / base
  let c4 := d.c4 + c3 / base
  let c5 := d.c5 + c4 / base
  let c6 := d.c6 + c5 / base
  let c7 := d.c7 + c6 / base
  let c8 := d.c8 + c7 / base
  let c9 := d.c9 + c8 / base
  ⟨d.c0, c1, c2, c3, c4, c5, c6, c7, c8, c9⟩

def sweep (d : Columns) : Columns :=
  let x := propagated d
  ⟨x.c0 % base + 5 * (x.c9 / base), x.c1 % base, x.c2 % base, x.c3 % base,
    x.c4 % base, x.c5 % base, x.c6 % base, x.c7 % base, x.c8 % base, x.c9 % base⟩

/-- Each carry sweep preserves the polynomial represented modulo 2^130 − 5. -/
theorem sweep_value (d : Columns) :
    value d = value (sweep d) + ((propagated d).c9 / base) * modulus := by
  simp only [value, sweep, propagated, base, modulus]
  omega

theorem sweep_congruence (d : Columns) : value (sweep d) % modulus = value d % modulus := by
  rw [sweep_value d, Nat.add_mod, Nat.mul_mod, Nat.mod_self, Nat.mul_zero, Nat.zero_mod,
    Nat.add_zero, Nat.mod_mod]

private theorem sweep_tail (d : Columns) : tailBounded (sweep d) base := by
  simp only [tailBounded, sweep]
  repeat' apply And.intro
  all_goals exact Nat.mod_lt _ (by decide)

/-- Every live scratch column in the sweep fits below the exact integer limit
of binary64. The power-of-two division computes an exact binary fraction. -/
theorem carry_intermediates_below_34_bits (d : Columns) (head : d.c0 < 2^33)
    (tail : tailBounded d (2^33)) : tailBounded (propagated d) (2^34) := by
  simp only [tailBounded] at tail
  rcases tail with ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩
  simp only [tailBounded, propagated, base]
  repeat' apply And.intro
  all_goals omega

private theorem first_head (d : Columns) (head : d.c0 < 2^33)
    (tail : tailBounded d (2^33)) : (sweep d).c0 < 6000000 := by
  simp only [tailBounded] at tail
  rcases tail with ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩
  simp only [sweep, propagated, base]
  omega

private theorem second_head (d : Columns) (head : d.c0 < 6000000)
    (tail : tailBounded d base) : (sweep d).c0 < base + 5 := by
  simp only [tailBounded, base] at tail
  rcases tail with ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩
  simp only [sweep, propagated, base]
  omega

private theorem third_head (d : Columns) (head : d.c0 < base + 5)
    (tail : tailBounded d base) : (sweep d).c0 < base := by
  simp only [tailBounded, base] at tail
  rcases tail with ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩
  simp only [base] at head
  simp only [sweep, propagated, base]
  by_cases small : d.c0 < 2^13 <;> omega

/-- Three carry sweeps normalize any ten convolution columns below 2^33. -/
theorem three_sweeps (d : Columns) (head : d.c0 < 2^33) (tail : tailBounded d (2^33)) :
    let reduced := sweep (sweep (sweep d))
    reduced.c0 < base ∧ tailBounded reduced base ∧
      value reduced % modulus = value d % modulus := by
  exact ⟨third_head _ (second_head _ (first_head d head tail) (sweep_tail d)) (sweep_tail _),
    sweep_tail _, by rw [sweep_congruence, sweep_congruence, sweep_congruence]⟩

/-- Before a carry sweep, each term in a folded column is below this uniform bound.
At most ten such terms contribute to a column. -/
theorem folded_term_bound (digit key : Nat) (hd : digit < 2 * base) (hk : key < base) :
    5 * digit * key ≤ 5 * (2 * base) * base :=
  Nat.mul_le_mul (Nat.mul_le_mul_left 5 (Nat.le_of_lt hd)) (Nat.le_of_lt hk)

theorem ten_terms_below_33_bits : 10 * (5 * (2 * base) * base) < 2^33 := by decide

#print axioms sweep_congruence
#print axioms three_sweeps
#print axioms folded_term_bound
#print axioms carry_intermediates_below_34_bits

end Abc.Spec.Poly1305.Radix13
