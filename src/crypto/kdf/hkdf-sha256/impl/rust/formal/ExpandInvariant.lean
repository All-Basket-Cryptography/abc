import HkdfSpec

namespace Abc.Refine.HkdfSha256

open Abc.Spec.Sha256 (Message)
open Abc.Spec.HkdfSha256

/-- Writing the first byte outside a prefix extends it by that byte. -/
theorem take_after_set {α : Type} (values : List α) (i : Nat) (value : α)
    (inside : i < values.length) :
    (values.set i value).take (i + 1) = values.take i ++ [value] := by
  induction values generalizing i with
  | nil => simp at inside
  | cons first rest smaller =>
    cases i with
    | zero => simp
    | succ i =>
      have less : i < rest.length := by simpa using inside
      simp [List.set, smaller i less]

/-- Any remaining writable byte requires a further RFC block. -/
theorem remaining_block {length written count : Nat}
    (offset : written = min (tagBytes * count) length) (remaining : written < length) :
    count < blockCount length := by
  by_cases completed : blockCount length ≤ count
  · have covered := (blockCount_le_iff length count).mp completed
    rw [Nat.min_eq_right covered] at offset
    omega
  · omega

theorem remaining_offset {length written count : Nat}
    (offset : written = min (tagBytes * count) length) (remaining : written < length) :
    written = tagBytes * count := by
  omega

theorem next_offset {length written count : Nat}
    (offset : written = min (tagBytes * count) length) (remaining : written < length) :
    min (written + tagBytes) length = min (tagBytes * (count + 1)) length := by
  rw [remaining_offset offset remaining, Nat.mul_succ]

/-- Finishing the output requires exactly the RFC's ceiling number of blocks. -/
theorem completed_blocks {length written count : Nat}
    (offset : written = min (tagBytes * count) length) (done : length ≤ written)
    (within : count ≤ blockCount length) : count = blockCount length := by
  apply Nat.le_antisymm within
  apply (blockCount_le_iff length count).mpr
  omega

/-- A partial final block contributes exactly the bytes that fit. -/
theorem take_material_succ (prk info : Message) (count written next : Nat)
    (complete : (material prk info count).length = written) (advances : written ≤ next) :
    (material prk info (count + 1)).take next =
      (material prk info count).take written ++ (block prk info (count + 1)).take (next - written) := by
  rw [material, List.take_append,
    List.take_of_length_le (show (material prk info count).length ≤ next by omega),
    List.take_of_length_le (Nat.le_of_eq complete), complete]

end Abc.Refine.HkdfSha256
