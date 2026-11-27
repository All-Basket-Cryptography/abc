namespace Abc.Keccak.CppTables

abbrev Coordinate := Nat × Nat

def destination (x y : Nat) : Coordinate := (y, (2 * x + 3 * y) % 5)

def cycle : Nat → Coordinate
  | 0 => (1, 0)
  | step + 1 => let (x, y) := cycle step; destination x y

def lane (p : Coordinate) : Nat := p.1 + 5 * p.2
def offset (step : Nat) : Nat := ((step + 1) * (step + 2) / 2) % 64
def publishedOffsets : List Nat :=
  [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]

theorem cycle_offsets :
    ∀ step : Fin 24,
      offset step.val = publishedOffsets[lane (cycle step.val)]! ∧
        0 < offset step.val ∧ offset step.val < 64 := by decide

theorem cycle_returns : cycle 24 = cycle 0 := by decide

set_option maxRecDepth 4096 in
set_option maxHeartbeats 3000000 in
theorem cycle_visits_nonzero_lanes :
    ∀ step : Fin 24,
      (0 < lane (cycle step.val) ∧ lane (cycle step.val) < 25) ∧
      ∀ other : Fin 24, lane (cycle step.val) = lane (cycle other.val) → step = other := by
  decide

def lfsrStep (register : BitVec 8) : BitVec 8 :=
  (register <<< 1) ^^^ (if 128 ≤ register.toNat then 0x71 else 0)

def lfsr : Nat → BitVec 8
  | 0 => 1
  | step + 1 => lfsrStep (lfsr step)

def iota (round : Nat) : Nat :=
  (List.range 7).foldl
    (fun result bit =>
      if (lfsr (7 * round + bit)).toNat % 2 = 1 then result + 2^(2^bit - 1) else result) 0

def cppIota : List Nat :=
  [0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
   0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
   0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
   0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
   0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
   0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
   0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
   0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

set_option maxRecDepth 4096 in
set_option maxHeartbeats 3000000 in
theorem iota_matches_lfsr : (List.range 24).map iota = cppIota := by decide

#print axioms cycle_offsets
#print axioms cycle_returns
#print axioms cycle_visits_nonzero_lanes
#print axioms iota_matches_lfsr

end Abc.Keccak.CppTables
