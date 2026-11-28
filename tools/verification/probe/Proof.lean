import Aeneas
import Generated.Funs

open Aeneas
open Aeneas.Std

#setup_aeneas_simps

namespace Abc.Probe

def sumSpec (left right : Nat) : Nat := left + right

theorem boundedAddRefines (left right : U32) (fits : sumSpec left.val right.val ≤ U32.max) :
    Generated.bounded_add left right ⦃ result => result.val = sumSpec left.val right.val ⦄ := by
  unfold sumSpec at fits ⊢
  unfold Generated.bounded_add
  step <;> assumption

end Abc.Probe

#print axioms Abc.Probe.boundedAddRefines
