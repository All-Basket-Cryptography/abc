import Sha256Spec

namespace Abc.Refine.Sha256.Streaming

open Abc.Spec.Sha256

/-- Split bytes into complete 64-byte blocks and a short suffix. -/
def splitBlocks (bytes : Message) : List Message × Message :=
  if bytes.length < 64 then ([], bytes) else
    let rest := splitBlocks (bytes.drop 64)
    (bytes.take 64 :: rest.1, rest.2)
termination_by bytes.length
decreasing_by simp; omega

structure Partition (bytes : Message) (blocks : List Message) (pending : Message) : Prop where
  reconstruct : blocks.flatten ++ pending = bytes
  full : ∀ block ∈ blocks, block.length = 64
  short : pending.length < 64

theorem splitBlocks_partition (bytes : Message) :
    Partition bytes (splitBlocks bytes).1 (splitBlocks bytes).2 := by
  rw [splitBlocks]
  split
  next short =>
    exact ⟨rfl, by simp, short⟩
  next enough =>
    have tail := splitBlocks_partition (bytes.drop 64)
    constructor
    · simp only [List.flatten_cons, List.append_assoc, tail.reconstruct, List.take_append_drop]
    · intro block member
      rcases List.mem_cons.mp member with equal | later
      · subst block
        simp only [List.length_take]
        omega
      · exact tail.full block later
    · exact tail.short
termination_by bytes.length
decreasing_by simp; omega

theorem Partition.feed {message pending : Message} {blocks : List Message}
    (partition : Partition message blocks pending) (input : Message) :
    Partition (message ++ input) (blocks ++ (splitBlocks (pending ++ input)).1)
      (splitBlocks (pending ++ input)).2 := by
  have fresh := splitBlocks_partition (pending ++ input)
  constructor
  · simp only [List.flatten_append, List.append_assoc, fresh.reconstruct]
    rw [← List.append_assoc, partition.reconstruct]
  · intro block member
    exact (List.mem_append.mp member).elim (partition.full block) (fresh.full block)
  · exact fresh.short

/-- The successful write view keeps only the previously initialized prefix and new bytes. -/
def overwriteWindow (storage : Message) (offset : Nat) (input : Message) : Message :=
  storage.take offset ++ input ++ storage.drop (offset + input.length)

theorem overwrittenPrefix (storage input : Message) (offset : Nat) (valid : offset ≤ storage.length) :
    (overwriteWindow storage offset input).take (offset + input.length) =
      storage.take offset ++ input := by
  have prefixLength : (storage.take offset ++ input).length = offset + input.length := by
    simp [Nat.min_eq_left valid]
  rw [overwriteWindow, ← prefixLength, List.take_append_length]

/-- If the Rust update exits early after filling part of its pending block, no block is emitted. -/
theorem fill_buffer_short (pending input : Message) (short : pending.length < 64)
    (inputShort : input.length < 64 - pending.length) :
    splitBlocks (pending ++ input) =
      ([], pending ++ input.take (min (64 - pending.length) input.length)) := by
  have lengthShort : (pending ++ input).length < 64 := by simp; omega
  rw [splitBlocks, if_pos lengthShort, Nat.min_eq_right (by omega)]
  simp

/-- A completed pending block is emitted before splitting the remaining input into blocks. -/
theorem fill_buffer_full (pending input : Message) (short : pending.length < 64)
    (enough : 64 - pending.length ≤ input.length) :
    splitBlocks (pending ++ input) =
      ((pending ++ input.take (64 - pending.length)) ::
        (splitBlocks (input.drop (64 - pending.length))).1,
        (splitBlocks (input.drop (64 - pending.length))).2) := by
  have lengthFull : ¬ (pending ++ input).length < 64 := by simp; omega
  have takePending : pending.take 64 = pending := List.take_of_length_le (by omega)
  have dropPending : pending.drop 64 = [] := List.drop_eq_nil_of_le (by omega)
  rw [splitBlocks, if_neg lengthFull, List.take_append, List.drop_append, takePending, dropPending]
  simp

def counterLimit : Nat := 18446744073709551616

def counterMaximum : Nat := 2305843009213693951

theorem length_cast_round_trip (incoming pointerLimit : Nat) (fitsPointer : incoming < pointerLimit) :
    incoming % counterLimit % pointerLimit = incoming ↔ incoming < counterLimit := by
  constructor
  · intro equal
    have smaller := Nat.mod_le (incoming % counterLimit) pointerLimit
    have fits := Nat.mod_lt incoming (by decide : 0 < counterLimit)
    omega
  · intro fits
    rw [Nat.mod_eq_of_lt fits, Nat.mod_eq_of_lt fitsPointer]

/-- Model the Rust length cast followed by the subtraction-based capacity check. -/
def checkedLength (prior incoming : Nat) : Option Nat :=
  if incoming < counterLimit ∧ incoming ≤ counterMaximum - prior
  then some (prior + incoming) else none

theorem checkedLength_matches_domain (prior incoming : Nat) (priorAllowed : byteLengthAllowed prior) :
    checkedLength prior incoming =
      if byteLengthAllowed (prior + incoming) then some (prior + incoming) else none := by
  have equiv :
      (incoming < counterLimit ∧ incoming ≤ counterMaximum - prior) ↔
      byteLengthAllowed (prior + incoming) := by
    change 8 * prior < 18446744073709551616 at priorAllowed
    change
      (incoming < 18446744073709551616 ∧ incoming ≤ 2305843009213693951 - prior) ↔
      8 * (prior + incoming) < 18446744073709551616
    omega
  simp only [checkedLength, equiv]

theorem bitLength_fits (length : Nat) (valid : byteLengthAllowed length) :
    length * 8 < counterLimit := by
  simpa [byteLengthAllowed, counterLimit, Nat.mul_comm] using valid

/-- The pending bytes are the live prefix of the Rust array. The stale suffix is outside this view. -/
structure BufferView (α : Type) where
  chaining : α
  pending : Message
  length : Nat

def Represents {α : Type} (initial : α) (compress : α → Message → α)
    (view : BufferView α) (message : Message) : Prop :=
  ∃ blocks, Partition message blocks view.pending ∧
    view.length = message.length ∧ byteLengthAllowed message.length ∧
    view.chaining = blocks.foldl compress initial

theorem initial_represents {α : Type} (initial : α) (compress : α → Message → α) :
    Represents initial compress ⟨initial, [], 0⟩ [] := by
  refine ⟨[], ⟨rfl, by simp, ?_⟩, rfl, ?_, rfl⟩
  · change 0 < 64
    decide
  decide

/-- The counter is checked before constructing a new buffer or updating the compression fold. -/
def update {α : Type} (compress : α → Message → α) (view : BufferView α) (input : Message) :
    Bool × BufferView α :=
  match checkedLength view.length input.length with
  | none => (false, view)
  | some length =>
    let split := splitBlocks (view.pending ++ input)
    (true, ⟨split.1.foldl compress view.chaining, split.2, length⟩)

theorem update_rejects_without_mutation {α : Type} (compress : α → Message → α)
    (view : BufferView α) (input : Message)
    (priorAllowed : byteLengthAllowed view.length)
    (disallowed : ¬ byteLengthAllowed (view.length + input.length)) :
    update compress view input = (false, view) := by
  simp [update, checkedLength_matches_domain _ _ priorAllowed, disallowed]

theorem update_preserves_representation {α : Type} {initial : α} {compress : α → Message → α}
    {view : BufferView α} {message : Message} (representation : Represents initial compress view message)
    (input : Message) (allowed : byteLengthAllowed (message.length + input.length)) :
    (update compress view input).1 = true ∧
      Represents initial compress (update compress view input).2 (message ++ input) := by
  rcases representation with ⟨blocks, partition, lengthEq, priorAllowed, foldEq⟩
  have accepted : checkedLength view.length input.length = some (message.length + input.length) := by
    rw [lengthEq, checkedLength_matches_domain _ _ priorAllowed, if_pos allowed]
  rw [update, accepted]
  refine ⟨rfl, blocks ++ (splitBlocks (view.pending ++ input)).1, partition.feed input, ?_, ?_, ?_⟩
  · simp
  · simpa using allowed
  · simp [List.foldl_append, foldEq]

/-- The two Rust finalization branches emit one or two blocks with the same length suffix. -/
def finalBlocks (pending : Message) (length : Nat) : List Message :=
  let suffix := Abc.Foundation.bytesBigEndian 8 (length * 8)
  if pending.length < 56 then
    [pending ++ [0x80] ++ List.replicate (55 - pending.length) 0 ++ suffix]
  else
    [pending ++ [0x80] ++ List.replicate (63 - pending.length) 0,
      List.replicate 56 0 ++ suffix]

theorem finalBlocks_full (pending : Message) (length : Nat) (short : pending.length < 64) :
    ∀ block ∈ finalBlocks pending length, block.length = 64 := by
  intro block member
  unfold finalBlocks at member
  split at member
  next beforeCutoff =>
    simp only [List.mem_singleton] at member
    subst block
    simp [Abc.Foundation.bytesBigEndian]
    omega
  next afterCutoff =>
    simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with first | second
    · subst block
      simp
      omega
    · subst block
      simp [Abc.Foundation.bytesBigEndian]

theorem finalBlocks_bytes (message pending : Message)
    (short : pending.length < 64) (remainder : message.length % 64 = pending.length) :
    (finalBlocks pending message.length).flatten = pending ++ padding message := by
  unfold finalBlocks
  change (if pending.length < 56 then
    [pending ++ [0x80] ++ List.replicate (55 - pending.length) 0 ++
      Abc.Foundation.bytesBigEndian 8 (message.length * 8)]
    else [pending ++ [0x80] ++ List.replicate (63 - pending.length) 0,
      List.replicate 56 0 ++ Abc.Foundation.bytesBigEndian 8 (message.length * 8)]).flatten =
    pending ++ ([0x80] ++ List.replicate ((119 - message.length % 64) % 64) 0 ++
      Abc.Foundation.bytesBigEndian 8 (8 * message.length))
  rw [remainder, Nat.mul_comm 8 message.length]
  split
  next beforeCutoff =>
    have zeros : (119 - pending.length) % 64 = 55 - pending.length := by omega
    simp [zeros, List.append_assoc]
  next afterCutoff =>
    have zeros : (119 - pending.length) % 64 = (63 - pending.length) + 56 := by omega
    simp only [List.flatten_cons, List.flatten_nil, List.append_nil, zeros, List.append_assoc]
    rw [← List.append_assoc (List.replicate (63 - pending.length) (0 : Byte)) (List.replicate 56 0),
      List.replicate_append_replicate]

theorem fullBlocks_length (blocks : List Message) (full : ∀ block ∈ blocks, block.length = 64) :
    blocks.flatten.length = 64 * blocks.length := by
  induction blocks with
  | nil => rfl
  | cons block rest smaller =>
    have first := full block (by simp)
    have later := smaller (fun next member => full next (List.mem_cons_of_mem block member))
    simp only [List.flatten_cons, List.length_append, List.length_cons, first, later]
    omega

theorem Partition.pending_remainder {message pending : Message} {blocks : List Message}
    (partition : Partition message blocks pending) : message.length % 64 = pending.length := by
  have short := partition.short
  rw [← partition.reconstruct, List.length_append, fullBlocks_length blocks partition.full]
  omega

private theorem indexedBlocks_match (blocks : List Message) (full : ∀ block ∈ blocks, block.length = 64) :
    (List.range blocks.length).map
      (fun index => (blocks.flatten.drop (index * 64)).take 64) = blocks := by
  induction blocks with
  | nil => rfl
  | cons first rest smaller =>
    have firstLength : first.length = 64 := full first (by simp)
    have remainingFull : ∀ block ∈ rest, block.length = 64 :=
      fun block member => full block (List.mem_cons_of_mem first member)
    have firstSlice : (first ++ rest.flatten).take 64 = first := by
      rw [← firstLength, List.take_append_length]
    have remainingSlices :
        (List.range rest.length).map
          (fun i => ((first ++ rest.flatten).drop (Nat.succ i * 64)).take 64) = rest := by
      calc
        _ = (List.range rest.length).map (fun i => (rest.flatten.drop (i * 64)).take 64) := by
          apply List.map_congr_left
          intro i _
          have headDropped : first.drop (Nat.succ i * 64) = [] :=
            List.drop_eq_nil_of_le (by omega)
          have tailOffset : Nat.succ i * 64 - first.length = i * 64 := by omega
          rw [List.drop_append, headDropped, List.nil_append, tailOffset]
        _ = rest := smaller remainingFull
    simp only [List.length_cons, List.range_succ_eq_map, List.map_cons, List.map_map,
      Function.comp_def, Nat.zero_mul, List.drop_zero, List.flatten_cons, firstSlice, remainingSlices]

theorem finalize_fold_refines {α : Type} {initial : α} {compress : α → Message → α}
    {view : BufferView α} {message : Message} (representation : Represents initial compress view message) :
    (finalBlocks view.pending view.length).foldl compress view.chaining =
      (List.range ((message ++ padding message).length / 64)).foldl
        (fun state i => compress state (((message ++ padding message).drop (i * 64)).take 64)) initial := by
  rcases representation with ⟨blocks, partition, lengthEq, _, foldEq⟩
  let completed := blocks ++ finalBlocks view.pending view.length
  have full : ∀ block ∈ completed, block.length = 64 := by
    intro block member
    exact (List.mem_append.mp member).elim (partition.full block)
      (finalBlocks_full view.pending view.length partition.short block)
  have wire : completed.flatten = message ++ padding message := by
    change (blocks ++ finalBlocks view.pending view.length).flatten = _
    rw [List.flatten_append, lengthEq,
      finalBlocks_bytes message view.pending partition.short partition.pending_remainder,
      ← List.append_assoc, partition.reconstruct]
  have count : completed.flatten.length / 64 = completed.length := by
    rw [fullBlocks_length completed full]
    omega
  have indexedFold : (List.range completed.length).foldl
      (fun state i => compress state ((completed.flatten.drop (i * 64)).take 64)) initial =
      completed.foldl compress initial := by
    calc
      _ = ((List.range completed.length).map
          (fun i => (completed.flatten.drop (i * 64)).take 64)).foldl compress initial := by
            rw [List.foldl_map]
      _ = _ := by rw [indexedBlocks_match completed full]
  rw [← wire, count, indexedFold]
  change _ = (blocks ++ finalBlocks view.pending view.length).foldl compress initial
  rw [List.foldl_append, ← foldEq]

def finalizeView (view : BufferView State) : List Byte :=
  encode ((finalBlocks view.pending view.length).foldl compress view.chaining)

theorem finalize_refines_digest {view : BufferView State} {message : Message}
    (representation : Represents initial compress view message) :
    some (finalizeView view) = digest message := by
  have valid : byteLengthAllowed message.length := by
    rcases representation with ⟨_, _, _, allowed, _⟩
    exact allowed
  rw [digest, if_pos valid]
  unfold finalizeView
  rw [finalize_fold_refines representation]

theorem update_refines_stream {α : Type} {initial : α} {compress : α → Message → α}
    {view : BufferView α} {message : Message} (representation : Represents initial compress view message)
    (input : Message) :
    let result := update compress view input
    match (Stream.mk message).update input with
    | none => result = (false, view)
    | some stream => result.1 = true ∧ Represents initial compress result.2 stream.message := by
  by_cases allowed : byteLengthAllowed (message.length + input.length)
  · simp only [Stream.update, if_pos allowed]
    exact update_preserves_representation representation input allowed
  · simp only [Stream.update, if_neg allowed]
    rcases representation with ⟨_, _, lengthEq, priorAllowed, _⟩
    exact update_rejects_without_mutation compress view input
      (by simpa [lengthEq] using priorAllowed) (by simpa [lengthEq] using allowed)

def digestView (message : Message) : Option (List Byte) :=
  let result := update compress ⟨initial, [], 0⟩ message
  if result.1 then some (finalizeView result.2) else none

theorem digestView_refines (message : Message) : digestView message = digest message := by
  by_cases allowed : byteLengthAllowed message.length
  · have step := update_preserves_representation (initial_represents initial compress) message
      (by simpa using allowed)
    unfold digestView
    rw [if_pos (by simpa using step.1)]
    exact finalize_refines_digest (by simpa using step.2)
  · have rejected := update_rejects_without_mutation compress ⟨initial, [], 0⟩ message
      (by change byteLengthAllowed 0; decide)
      (by simpa using allowed)
    simp [digestView, rejected, digest, allowed]

/-- A caller may continue after an error. Only accepted chunks contribute to its digest. -/
def acceptedAppend (message input : Message) : Message :=
  if byteLengthAllowed (message.length + input.length) then message ++ input else message

theorem trace_preserves_representation {α : Type} {initial : α} {compress : α → Message → α}
    {view : BufferView α} {message : Message}
    (representation : Represents initial compress view message) (chunks : List Message) :
    Represents initial compress
      (chunks.foldl (fun state input => (update compress state input).2) view)
      (chunks.foldl acceptedAppend message) := by
  induction chunks generalizing view message with
  | nil => exact representation
  | cons input remaining onward =>
    apply onward
    by_cases allowed : byteLengthAllowed (message.length + input.length)
    · simpa [acceptedAppend, allowed] using
        (update_preserves_representation representation input allowed).2
    · rcases representation with ⟨blocks, part, lengthEq, priorAllowed, foldEq⟩
      have rejected := update_rejects_without_mutation compress view input
        (by simpa [lengthEq] using priorAllowed) (by simpa [lengthEq] using allowed)
      simp [acceptedAppend, allowed, rejected]
      exact ⟨blocks, part, lengthEq, priorAllowed, foldEq⟩

theorem acceptedTrace_eq_concat (message : Message) (chunks : List Message)
    (allowed : byteLengthAllowed (message ++ chunks.flatten).length) :
    chunks.foldl acceptedAppend message = message ++ chunks.flatten := by
  induction chunks generalizing message with
  | nil => simp
  | cons input remaining onward =>
    have prefixAllowed : byteLengthAllowed (message.length + input.length) := by
      unfold byteLengthAllowed at *
      simp only [List.flatten_cons, List.length_append] at allowed
      omega
    have nextAllowed : byteLengthAllowed ((message ++ input) ++ remaining.flatten).length := by
      simpa only [List.flatten_cons, List.append_assoc] using allowed
    simp only [List.foldl_cons, acceptedAppend, if_pos prefixAllowed]
    rw [onward (message ++ input) nextAllowed, List.append_assoc, List.flatten_cons]

def finalizeTrace (chunks : List Message) : List Byte :=
  finalizeView (chunks.foldl (fun view input => (update compress view input).2) ⟨initial, [], 0⟩)

theorem finalizeTrace_refines_accepted (chunks : List Message) :
    some (finalizeTrace chunks) = digest (chunks.foldl acceptedAppend []) := by
  unfold finalizeTrace
  exact finalize_refines_digest (trace_preserves_representation (initial_represents initial compress) chunks)

theorem finalizeTrace_refines_concat (chunks : List Message)
    (allowed : byteLengthAllowed chunks.flatten.length) :
    some (finalizeTrace chunks) = digest chunks.flatten := by
  simpa using (finalizeTrace_refines_accepted chunks).trans (congrArg digest
    (acceptedTrace_eq_concat [] chunks (by simpa using allowed)))

end Abc.Refine.Sha256.Streaming
