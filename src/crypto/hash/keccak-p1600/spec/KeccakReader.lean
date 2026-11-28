import Std

namespace Abc.Spec.Keccak.Reader

abbrev Byte := BitVec 8

def nextTwo (i : Nat) : Nat :=
  if i < 8 then i + 2 else i - 8

def nextFour (i : Nat) : Nat :=
  if i < 6 then i + 4 else i - 6

theorem next_two_correct (i : Nat) (inside : i < 10) :
    nextTwo i = (i + 2) % 10 := by
  unfold nextTwo
  split <;> omega

theorem next_four_correct (i : Nat) (inside : i < 10) :
    nextFour i = (i + 4) % 10 := by
  unfold nextFour
  split <;> omega

/-- Each row uses ten 32-bit limbs. Adding two or four chooses the same half
of the next Keccak lane, including both wraparound regions. -/
theorem chi_row_matches (row : Nat → BitVec 32) (i : Fin 10) :
    row i.val ^^^ ((~~~ row (nextTwo i.val)) &&& row (nextFour i.val)) =
      row i.val ^^^ ((~~~ row ((i.val + 2) % 10)) &&& row ((i.val + 4) % 10)) := by
  rw [next_two_correct _ i.isLt, next_four_correct _ i.isLt]

structure Cursor where
  block : Nat
  within : Nat
  withinRate : within ≤ 136

def Cursor.offset (cursor : Cursor) : Nat :=
  136 * cursor.block + cursor.within

/-- Reaching offset 136 is a legal paused state. Refresh occurs on the next
nonempty read, and the absolute input-independent position is preserved. -/
def ready (cursor : Cursor) : Cursor :=
  if cursor.within = 136 then ⟨cursor.block + 1, 0, by decide⟩ else cursor

theorem ready_inside (cursor : Cursor) : (ready cursor).within < 136 := by
  unfold ready
  split
  · simp
  · have := cursor.withinRate
    omega

theorem ready_offset (cursor : Cursor) : (ready cursor).offset = cursor.offset := by
  unfold ready
  split <;> simp_all [Cursor.offset, Nat.mul_add] <;> omega

def spanCount (cursor : Cursor) (remaining : Nat) : Nat :=
  min (136 - (ready cursor).within) remaining

theorem span_progress (cursor : Cursor) {remaining : Nat} (positive : 0 < remaining) :
    0 < spanCount cursor remaining ∧ spanCount cursor remaining ≤ remaining := by
  have fits := ready_inside cursor
  unfold spanCount
  omega

def after (cursor : Cursor) (remaining : Nat) : Cursor :=
  ⟨(ready cursor).block, (ready cursor).within + spanCount cursor remaining, by
    have := ready_inside cursor
    unfold spanCount
    omega⟩

theorem after_offset (cursor : Cursor) (remaining : Nat) :
    (after cursor remaining).offset = cursor.offset + spanCount cursor remaining := by
  change 136 * (ready cursor).block + ((ready cursor).within + spanCount cursor remaining) = _
  rw [← Nat.add_assoc]
  change (ready cursor).offset + spanCount cursor remaining = _
  rw [ready_offset]

theorem span_stays_in_block (cursor : Cursor) (remaining displacement : Nat)
    (inside : displacement < spanCount cursor remaining) :
    (cursor.offset + displacement) / 136 = (ready cursor).block ∧
      (cursor.offset + displacement) % 136 = (ready cursor).within + displacement := by
  have width := (ready cursor).withinRate
  rw [← ready_offset cursor]
  unfold Cursor.offset spanCount at *
  omega

/-- The source enumerates the ordered bytes of the squeezed rate blocks. -/
def span (source : Nat → Byte) (cursor : Cursor) (remaining : Nat) : List Byte :=
  (List.range' (ready cursor).within (spanCount cursor remaining)).map
    (fun i => source (136 * (ready cursor).block + i))

theorem span_bytes (source : Nat → Byte) (cursor : Cursor) (remaining : Nat) :
    span source cursor remaining =
      (List.range' cursor.offset (spanCount cursor remaining)).map source := by
  rw [← ready_offset cursor]
  simp [span, List.range'_eq_map_range, List.map_map, Function.comp_def, Cursor.offset, Nat.add_assoc]

def read (source : Nat → Byte) (cursor : Cursor) (remaining : Nat) : List Byte × Cursor :=
  if _empty : remaining = 0 then ([], cursor)
  else
    let count := spanCount cursor remaining
    let suffix := read source (after cursor remaining) (remaining - count)
    (span source cursor remaining ++ suffix.1, suffix.2)
termination_by remaining
decreasing_by
  have := span_progress cursor (Nat.pos_of_ne_zero _empty)
  simp_wf
  omega

theorem read_correct (source : Nat → Byte) (cursor : Cursor) (remaining : Nat) :
    (read source cursor remaining).1 = (List.range' cursor.offset remaining).map source ∧
      (read source cursor remaining).2.offset = cursor.offset + remaining := by
  by_cases empty : remaining = 0
  · subst remaining
    rw [read]
    simp
  · have h := span_progress cursor (Nat.pos_of_ne_zero empty)
    have smaller : remaining - spanCount cursor remaining < remaining := by omega
    obtain ⟨bytes, position⟩ := read_correct source (after cursor remaining)
      (remaining - spanCount cursor remaining)
    have full : spanCount cursor remaining + (remaining - spanCount cursor remaining) = remaining := by omega
    rw [read]
    simp only [dif_neg empty, span_bytes, bytes, position, after_offset]
    constructor
    · rw [← List.map_append]
      have concatenate := @List.range'_append cursor.offset (spanCount cursor remaining)
        (remaining - spanCount cursor remaining) 1
      simpa only [Nat.one_mul, full] using congrArg (List.map source) concatenate
    · omega
termination_by remaining

def readTrace (source : Nat → Byte) (cursor : Cursor) : List Nat → List Byte × Cursor
  | [] => ([], cursor)
  | count :: rest =>
    let first := read source cursor count
    let suffix := readTrace source first.2 rest
    (first.1 ++ suffix.1, suffix.2)

theorem read_trace_correct (source : Nat → Byte) (cursor : Cursor) (requests : List Nat) :
    (readTrace source cursor requests).1 = (read source cursor requests.sum).1 ∧
      (readTrace source cursor requests).2.offset = (read source cursor requests.sum).2.offset := by
  induction requests generalizing cursor with
  | nil =>
    simp [readTrace, read]
  | cons count rest ih =>
    obtain ⟨out1, pos1⟩ := read_correct source cursor count
    obtain ⟨out2, pos2⟩ := ih (read source cursor count).2
    have suffix := read_correct source (read source cursor count).2 rest.sum
    have whole := read_correct source cursor (count + rest.sum)
    simp only [readTrace, List.sum_cons]
    constructor
    · rw [out1, out2, suffix.1, whole.1, pos1, ← List.map_append]
      have concatenate := @List.range'_append cursor.offset count rest.sum 1
      simpa only [Nat.one_mul] using congrArg (List.map source) concatenate
    · rw [pos2, suffix.2, pos1, whole.2]
      omega

#print axioms chi_row_matches
#print axioms span_stays_in_block
#print axioms read_correct
#print axioms read_trace_correct

end Abc.Spec.Keccak.Reader
