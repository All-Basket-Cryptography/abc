import ScryptFunctional

namespace Abc.Spec.Scrypt.Alternating

open Abc.Spec.Scrypt.Functional

structure Buffers (α : Type) where
  lane : α
  scratch : α
  readScratch : Bool

def current (buffers : Buffers α) : α :=
  if buffers.readScratch then buffers.scratch else buffers.lane

/-- Read only the current lane, write the entire other buffer and exchange their roles. -/
def writeAndSwap (mix : α → α) (before : Buffers α) : Buffers α :=
  if before.readScratch then ⟨mix before.scratch, before.scratch, false⟩
  else ⟨before.lane, mix before.lane, true⟩

theorem current_step (mix : α → α) (before : Buffers α) :
    current (writeAndSwap mix before) = mix (current before) := by
  cases mode : before.readScratch <;> simp [current, writeAndSwap, mode]

theorem current_iterations (mix : α → α) (before : Buffers α) (count : Nat) :
    current (iterate (writeAndSwap mix) before count) = iterate mix (current before) count := by
  induction count with
  | zero => rfl
  | succ count ih => simp only [iterate, current_step, ih]

private theorem two_swaps_restore (mix : α → α) (before : Buffers α) :
    (writeAndSwap mix (writeAndSwap mix before)).readScratch = before.readScratch := by
  cases position : before.readScratch <;> simp [writeAndSwap, position]

theorem even_swaps_restore (mix : α → α) (before : Buffers α) (pairs : Nat) :
    (iterate (writeAndSwap mix) before (2 * pairs)).readScratch = before.readScratch := by
  induction pairs with
  | zero => rfl
  | succ pairs ih =>
    rw [Nat.mul_succ]
    exact (two_swaps_restore mix _).trans ih

def storeRows (mix : α → α) (initial : Buffers α) : Nat → Buffers α × Array α
  | 0 => (initial, #[])
  | n + 1 =>
    let previous := storeRows mix initial n
    (writeAndSwap mix previous.1, previous.2.push (current previous.1))

private theorem store_position (mix : α → α) (initial : Buffers α) (count : Nat) :
    (storeRows mix initial count).1 = iterate (writeAndSwap mix) initial count := by
  induction count with
  | zero => rfl
  | succ count ih => simp only [storeRows, iterate, ih]

/-- The table keeps a snapshot of the active lane before every BlockMix. -/
theorem store_logical (mix : α → α) (initial : Buffers α) (count : Nat) :
    (current (storeRows mix initial count).1, (storeRows mix initial count).2) =
      fillTable mix (current initial) count := by
  induction count with
  | zero => rfl
  | succ count ih =>
    simp only [storeRows, fillTable, current_step]
    exact congrArg (fun (row : α × Array α) => (mix row.1, row.2.push row.1)) ih

def romix (ops : LaneOps α) (lane scratch : α) (width exponent : Nat) : Buffers α :=
  let count := 2 ^ exponent
  let saved := storeRows ops.blockMix ⟨lane, scratch, false⟩ count
  iterate (writeAndSwap (fun value =>
    let row := machineIndex (ops.integerify value) width exponent
    ops.blockMix (ops.xor value (saved.2.getD row lane)))) saved.1 count

theorem logical_romix (ops : LaneOps α) (lane scratch : α) (width exponent : Nat) :
    current (romix ops lane scratch width exponent) = workspaceRomix ops lane width exponent := by
  let saved := storeRows ops.blockMix ⟨lane, scratch, false⟩ (2 ^ exponent)
  have capture : (current saved.1, saved.2) = fillTable ops.blockMix lane (2 ^ exponent) :=
    store_logical ops.blockMix ⟨lane, scratch, false⟩ _
  unfold romix workspaceRomix
  rw [current_iterations]
  change _ = (match fillTable ops.blockMix lane (2 ^ exponent) with
    | (before, table) => iterate (fun value =>
        ops.blockMix (ops.xor value (table.getD (machineIndex (ops.integerify value) width exponent) lane)))
        before (2 ^ exponent))
  rw [← capture]

/-- Both passes have an even number of steps for every admissible power-of-two cost.
Thus the returned lane is the caller's original buffer and needs no copy-back. -/
theorem romix_returns_to_lane (ops : LaneOps α) (lane scratch : α) (width exponent : Nat) :
    (romix ops lane scratch width (exponent + 1)).readScratch = false := by
  simp only [romix, Nat.pow_succ, Nat.mul_comm (2 ^ exponent) 2]
  rw [even_swaps_restore, store_position, even_swaps_restore]

theorem caller_lane_refines (ops : LaneOps α) (lane scratch : α) (width exponent : Nat)
    (inWord : exponent + 1 ≤ 64) (inPointer : exponent + 1 ≤ width) :
    (romix ops lane scratch width (exponent + 1)).lane = rfcRomix ops lane (2 ^ (exponent + 1)) := by
  have logical := logical_romix ops lane scratch width (exponent + 1)
  rw [current, romix_returns_to_lane, if_neg Bool.false_ne_true] at logical
  exact logical.trans (romix_refines _ _ _ _ inWord inPointer)

theorem construction_refines_with_swaps
    (providerPbkdf2 rfcPbkdf2 : Pbkdf2) (providerSalsa rfcSalsa : Chunk → Chunk)
    (password salt scratch : Bytes) (r lanes output width exponent : Nat)
    (pbkdf2Contract : ∀ p s n, providerPbkdf2 p s 1 n = rfcPbkdf2 p s 1 n)
    (salsaContract : ∀ block, providerSalsa block = rfcSalsa block)
    (inWord : exponent + 1 ≤ 64) (inPointer : exponent + 1 ≤ width) :
    deriveWith providerPbkdf2
      (fun lane => (romix (byteOps providerSalsa r) lane scratch width (exponent + 1)).lane)
      password salt r lanes output =
    deriveWith rfcPbkdf2 (fun lane => rfcRomix (byteOps rfcSalsa r) lane (2 ^ (exponent + 1)))
      password salt r lanes output := by
  have equalSalsa : providerSalsa = rfcSalsa := funext salsaContract
  subst providerSalsa
  simp only [deriveWith, pbkdf2Contract, caller_lane_refines _ _ _ _ _ inWord inPointer]

#print axioms current_iterations
#print axioms even_swaps_restore
#print axioms store_logical
#print axioms logical_romix
#print axioms romix_returns_to_lane
#print axioms caller_lane_refines
#print axioms construction_refines_with_swaps

end Abc.Spec.Scrypt.Alternating
