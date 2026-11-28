namespace Abc.Spec.Ed25519.Jvm

def prime : Nat := 2 ^ 255 - 19
def subgroupOrder : Nat := 2 ^ 252 + 27742317777372353535851937790883648493
def curveD : Nat := 37095705934669439343138083508754565189542113879843219016388785533085940283555
def sqrtMinusOne : Nat := 19681161376707505956807079304988542015446066515923890162744021073123829784752

theorem curve_constant : (curveD * 121666 + 121665) % prime = 0 := by decide

theorem square_root_constant : (sqrtMinusOne * sqrtMinusOne) % prime = prime - 1 := by decide

theorem encoded_scalar_fits (scalar : Nat) (canonical : scalar < subgroupOrder) : scalar < 2 ^ 253 := by
  unfold subgroupOrder at canonical
  omega

theorem scalar_with_added_order_rejected (scalar : Nat) : ¬ scalar + subgroupOrder < subgroupOrder := by
  omega

-- The four extended coordinates returned by the polynomial doubling formula
-- satisfy X*Y = Z*T as a polynomial before reduction in the field.
theorem extended_coordinates (e f g h : Int) : (e * f) * (g * h) = (f * g) * (e * h) := by
  ac_rfl

theorem cofactor_schedule {Point : Type} (multiple : Nat → Point) (twice : Point → Point)
    (addition : ∀ n, twice (multiple n) = multiple (n + n)) :
    twice (twice (twice (multiple 1))) = multiple 8 := by
  rw [addition, addition, addition]

#print axioms curve_constant
#print axioms square_root_constant
#print axioms encoded_scalar_fits
#print axioms scalar_with_added_order_rejected
#print axioms extended_coordinates
#print axioms cofactor_schedule

end Abc.Spec.Ed25519.Jvm
