namespace Abc.Spec.EcdsaP256.Jvm

def order : Nat := 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

theorem scalar_fits_unsigned_width (x : Nat) (within : x < order) : x < 2 ^ 256 := by
  unfold order at within
  omega

theorem alternate_s_within_order (s : Nat) (positive : 0 < s) (within : s < order) :
    0 < order - s ∧ order - s < order := by
  omega

theorem p1363_halves (r s : List UInt8) (rWidth : r.length = 32) :
    (r ++ s).take 32 = r ∧ (r ++ s).drop 32 = s := by
  rw [← rWidth]
  simp

#print axioms scalar_fits_unsigned_width
#print axioms alternate_s_within_order
#print axioms p1363_halves

end Abc.Spec.EcdsaP256.Jvm
