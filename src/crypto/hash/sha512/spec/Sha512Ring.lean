namespace Abc.Spec.Sha512Ring

abbrev Word := BitVec 64
abbrev Schedule := Nat → Word

def small0 (x : Word) : Word := x.rotateRight 1 ^^^ x.rotateRight 8 ^^^ (x >>> 7)
def small1 (x : Word) : Word := x.rotateRight 19 ^^^ x.rotateRight 61 ^^^ (x >>> 6)

def recurrence (schedule : Schedule) (i : Nat) : Word :=
  small1 (schedule (i - 2)) + schedule (i - 7) + small0 (schedule (i - 15)) + schedule (i - 16)

def window (schedule ring : Schedule) (i : Nat) : Prop :=
  ∀ d, 1 ≤ d → d ≤ 16 → ring ((i - d) % 16) = schedule (i - d)

def advance (ring : Schedule) (i : Nat) : Schedule :=
  fun slot =>
    if slot = i % 16 then
      ring (i % 16) + (small0 (ring ((i - 15) % 16)) +
        ring ((i - 7) % 16) + small1 (ring ((i - 2) % 16)))
    else ring slot

theorem next_word (schedule ring : Schedule) (i : Nat) (lower : 16 ≤ i)
    (live : window schedule ring i) :
    advance ring i (i % 16) = recurrence schedule i := by
  have oldest : (i - 16) % 16 = i % 16 := by omega
  unfold advance recurrence
  rw [if_pos rfl, ← oldest, live 16 (by decide) (by decide),
    live 15 (by decide) (by decide), live 7 (by decide) (by decide),
    live 2 (by decide) (by decide)]
  have swap (a b c : Word) : a + (b + c) = b + (a + c) := by
    rw [← BitVec.add_assoc, BitVec.add_comm a b, BitVec.add_assoc]
  simp only [BitVec.add_assoc, BitVec.add_comm, swap]

theorem advance_preserves_window (schedule ring : Schedule) (i : Nat)
    (lower : 16 ≤ i) (live : window schedule ring i) (step : schedule i = recurrence schedule i) :
    window schedule (advance ring i) (i + 1) := by
  intro d atLeast atMost
  by_cases first : d = 1
  · simp only [first, Nat.add_sub_cancel, next_word schedule ring i lower live, step]
  · have earlier : i + 1 - d = i - (d - 1) := by omega
    have distinct : (i - (d - 1)) % 16 ≠ i % 16 := by omega
    rw [earlier]
    exact (if_neg distinct).trans (live (d - 1) (by omega) (by omega))

def after (initial : Schedule) : Nat → Schedule
  | 0 => initial
  | n + 1 => advance (after initial n) (16 + n)

theorem all_expansion_steps (schedule initial : Schedule)
    (first : ∀ i, i < 16 → initial i = schedule i)
    (rest : ∀ i, 16 ≤ i → schedule i = recurrence schedule i) (steps : Nat) :
    window schedule (after initial steps) (16 + steps) := by
  induction steps with
  | zero =>
    intro d atLeast atMost
    change initial ((16 - d) % 16) = schedule (16 - d)
    have inside : 16 - d < 16 := by omega
    simpa only [Nat.mod_eq_of_lt inside] using first (16 - d) inside
  | succ n previous =>
    exact advance_preserves_window schedule (after initial n) (16 + n)
      (by omega) previous (rest (16 + n) (by omega))

#print axioms next_word
#print axioms advance_preserves_window
#print axioms all_expansion_steps

end Abc.Spec.Sha512Ring
