import Lean

namespace Abc.Probe.Fixtures

private theorem incomplete : False := by sorry

theorem transitiveSorry : False := incomplete

axiom unapproved : False

theorem customAxiom : False := unapproved

theorem nativeEvaluation : 1 + 1 = 2 := by native_decide

end Abc.Probe.Fixtures

#print axioms Abc.Probe.Fixtures.transitiveSorry
#print axioms Abc.Probe.Fixtures.customAxiom
#print axioms Abc.Probe.Fixtures.nativeEvaluation
