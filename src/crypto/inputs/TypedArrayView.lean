namespace Abc.Spec.EcmaView

inductive Kind where
  | byte | word
  deriving DecidableEq

def Kind.width : Kind → Nat
  | .byte => 1
  | .word => 4

inductive Extent where
  | fixed (elements : Nat)
  | tracking

/-- The intrinsic tag and buffer slots observed at synchronous API entry.
`currentBytes = none` models a detached buffer. -/
structure Input where
  tag : Option Kind
  shared : Bool
  currentBytes : Option Nat
  offset : Nat
  extent : Extent

structure Fixed where
  offset : Nat
  elements : Nat
  deriving DecidableEq

def inBounds (kind : Kind) (input : Input) (length : Nat) : Prop :=
  match input.extent with
  | .fixed elements => input.offset + elements * kind.width ≤ length
  | .tracking => input.offset ≤ length

instance (kind : Kind) (input : Input) (length : Nat) : Decidable (inBounds kind input length) := by
  unfold inBounds
  split <;> infer_instance

def currentElements (kind : Kind) (input : Input) (length : Nat) : Nat :=
  match input.extent with
  | .fixed elements => elements
  | .tracking => (length - input.offset) / kind.width

def accessLength (kind : Kind) (input : Input) : Nat :=
  match input.currentBytes with
  | none => 0
  | some length => if inBounds kind input length then currentElements kind input length else 0

def validateAtZero (kind : Kind) (input : Input) : Bool :=
  match input.currentBytes with
  | none => false
  | some length => decide (inBounds kind input length)

/-- Model of the native accessor sequence, including the empty-view check.
Range validation uses a stable single snapshot of the backing slots. -/
def capture (kind : Kind) (input : Input) : Option Fixed :=
  if input.tag ≠ some kind ∨ input.shared = true then none else
    let count := accessLength kind input
    if count = 0 ∧ validateAtZero kind input = false then none
    else some ⟨input.offset, count⟩

/-- Direct admission and range specification for the given byte or word type. -/
def contract (kind : Kind) (input : Input) : Option Fixed :=
  match input.currentBytes with
  | none => none
  | some length =>
    if input.tag = some kind ∧ input.shared = false ∧ inBounds kind input length
    then some ⟨input.offset, currentElements kind input length⟩ else none

theorem capture_refines_contract (kind : Kind) (input : Input) : capture kind input = contract kind input := by
  by_cases brand : input.tag = some kind
  · cases shared : input.shared with
    | true => cases length : input.currentBytes <;> simp [capture, contract, shared, length]
    | false =>
      cases length : input.currentBytes with
      | none => simp [capture, contract, brand, shared, length, accessLength, validateAtZero]
      | some size =>
        by_cases bounds : inBounds kind input size <;>
          simp [capture, contract, brand, shared, length, accessLength, validateAtZero, bounds]
  · cases length : input.currentBytes <;> simp [capture, contract, brand, length]

theorem capture_footprint (kind : Kind) (input : Input) (result : Fixed)
    (success : capture kind input = some result) : ∃ length,
      input.currentBytes = some length ∧ result.offset = input.offset ∧
        result.offset + result.elements * kind.width ≤ length := by
  rw [capture_refines_contract] at success
  cases length : input.currentBytes with
  | none => simp [contract, length] at success
  | some bound =>
    simp only [contract, length] at success
    split at success
    · rename_i valid
      cases success
      refine ⟨bound, rfl, rfl, ?_⟩
      have within := valid.2.2
      cases extent : input.extent with
      | fixed elements => simpa [inBounds, currentElements, extent] using within
      | tracking =>
        simp only [inBounds, extent] at within
        simp only [currentElements, extent]
        have floor := Nat.div_mul_le_self (bound - input.offset) kind.width
        omega
    · contradiction

theorem captured_fixed_range (kind : Kind) (input : Input) (result : Fixed) (length : Nat)
    (success : capture kind input = some result) (grew : ∀ old, input.currentBytes = some old → old ≤ length) :
    inBounds kind {input with currentBytes := some length, extent := .fixed result.elements} length := by
  obtain ⟨old, size, offset, fits⟩ := capture_footprint kind input result success
  simpa [inBounds, offset] using Nat.le_trans fits (grew old size)

#print axioms capture_refines_contract
#print axioms capture_footprint
#print axioms captured_fixed_range

end Abc.Spec.EcmaView
